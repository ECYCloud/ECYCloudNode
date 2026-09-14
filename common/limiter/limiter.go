// Package limiter is to control the links that go into the dispatcher
package limiter

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/time/rate"

	"github.com/ECYCloud/ECYCloudNode/api"
)

const (
	// OnlineSlotExpiry 名额 无活动超过该时长即视为下线，释放设备名额
	OnlineSlotExpiry = time.Minute
	// onlineTouchSec 存活连接刷新在线状态/复查名额的间隔（秒）
	onlineTouchSec = 10
)

type UserInfo struct {
	UID         int
	ClientID    int
	SpeedLimit  uint64
	DeviceLimit int
}

// onlineEntry 记录单个在线 名额 的归属与最近活跃时间（unix 秒）
type onlineEntry struct {
	UID      int
	LastSeen int64
}

type InboundInfo struct {
	Tag             string
	NodeSpeedLimit  uint64
	UserInfo        *sync.Map // Key: user identifier (usually UID string) -> UserInfo
	BucketHub       *sync.Map // Key: user identifier -> *rate.Limiter
	UserOnlineSlots *sync.Map // Key: onlineBucket() -> *sync.Map (Key: OnlineKey(), Value: onlineEntry)
	GlobalLimit     *GlobalDeviceChecker
}

// onlineBucket 名额账本的分桶键。官方客户端每台设备有独立 userKey，必须并到账号级
// 桶里才数得出「该账号几台在线」；官方与第三方分桶，两组各自独立使用同一个上限。
func onlineBucket(tag string, uid, clientID int) string {
	if clientID != 0 {
		return fmt.Sprintf("%s|%d|client", tag, uid)
	}
	return fmt.Sprintf("%s|%d", tag, uid)
}

type Limiter struct {
	InboundInfo *sync.Map // Key: Tag, Value: *InboundInfo
}

func New() *Limiter {
	return &Limiter{
		InboundInfo: new(sync.Map),
	}
}

func (l *Limiter) AddInboundLimiter(tag string, nodeSpeedLimit uint64, userList *[]api.UserInfo, globalLimit *GlobalDeviceLimitConfig) error {
	inboundInfo := &InboundInfo{
		Tag:             tag,
		NodeSpeedLimit:  nodeSpeedLimit,
		BucketHub:       new(sync.Map),
		UserOnlineSlots: new(sync.Map),
		GlobalLimit:     NewGlobalDeviceChecker(globalLimit),
	}

	userMap := new(sync.Map)
	for _, u := range *userList {
		userKey := u.Key(tag)
		userMap.Store(userKey, UserInfo{
			UID:         u.UID,
			ClientID:    u.ClientID,
			SpeedLimit:  u.SpeedLimit,
			DeviceLimit: u.DeviceLimit,
		})
	}
	inboundInfo.UserInfo = userMap
	l.InboundInfo.Store(tag, inboundInfo) // Replace the old inbound info
	return nil
}

func (l *Limiter) UpdateInboundLimiter(tag string, updatedUserList *[]api.UserInfo) error {
	if value, ok := l.InboundInfo.Load(tag); ok {
		inboundInfo := value.(*InboundInfo)
		// Update User info
		for _, u := range *updatedUserList {
			userKey := u.Key(tag)
			inboundInfo.UserInfo.Store(userKey, UserInfo{
				UID:         u.UID,
				ClientID:    u.ClientID,
				SpeedLimit:  u.SpeedLimit,
				DeviceLimit: u.DeviceLimit,
			})
			if u.ClientID != 0 {
				userKey = fmt.Sprintf("%s|%d", tag, u.UID)
			}
			// Update old limiter bucket
			limit := determineRate(inboundInfo.NodeSpeedLimit, u.SpeedLimit)
			if limit > 0 {
				if bucket, ok := inboundInfo.BucketHub.Load(userKey); ok {
					lim := bucket.(*rate.Limiter)
					lim.SetLimit(rate.Limit(limit))
					lim.SetBurst(int(limit))
				}
			} else {
				inboundInfo.BucketHub.Delete(userKey)
			}
		}
	} else {
		return fmt.Errorf("no such inbound in limiter: %s", tag)
	}
	return nil
}

func (l *Limiter) DeleteInboundLimiter(tag string) error {
	l.InboundInfo.Delete(tag)
	return nil
}

func (l *Limiter) GetOnlineDevice(tag string) (*[]api.OnlineUser, error) {
	var onlineUser []api.OnlineUser

	if value, ok := l.InboundInfo.Load(tag); ok {
		inboundInfo := value.(*InboundInfo)
		now := time.Now().Unix()
		// 只清理过期 名额，保留活跃 名额 的在线状态。
		// 整表清空会导致每个上报周期设备名额被重新抢占，使设备限制形同虚设。
		inboundInfo.UserOnlineSlots.Range(func(key, value interface{}) bool {
			email := key.(string)
			slotMap := value.(*sync.Map)
			active := 0
			slotMap.Range(func(slotKey, entryValue interface{}) bool {
				entry := entryValue.(onlineEntry)
				if now-entry.LastSeen > int64(OnlineSlotExpiry/time.Second) {
					slotMap.Delete(slotKey)
					return true
				}
				active++
				slot := slotKey.(string)
				onlineUser = append(onlineUser, OnlineUser(entry.UID, slot))
				return true
			})
			if active == 0 {
				// 用户已完全下线：释放在线表与限速桶
				inboundInfo.UserOnlineSlots.Delete(email)
				inboundInfo.BucketHub.Delete(email)
			}
			return true
		})
	} else {
		return nil, fmt.Errorf("no such inbound in limiter: %s", tag)
	}

	return &onlineUser, nil
}

func (l *Limiter) GetUserBucket(tag string, userKey string, ip string) (limiter *rate.Limiter, SpeedLimit bool, Reject bool) {
	if value, ok := l.InboundInfo.Load(tag); ok {
		var (
			userLimit                  uint64
			deviceLimit, uid, clientID int
		)

		inboundInfo := value.(*InboundInfo)
		nodeLimit := inboundInfo.NodeSpeedLimit

		if v, ok := inboundInfo.UserInfo.Load(userKey); ok {
			u := v.(UserInfo)
			uid = u.UID
			userLimit = u.SpeedLimit
			deviceLimit = u.DeviceLimit
			clientID = u.ClientID
		}

		if !admitSlot(inboundInfo, userKey, ip, uid, deviceLimit) {
			return nil, false, true
		}

		if clientID != 0 {
			userKey = fmt.Sprintf("%s|%d", tag, uid)
		}
		// Speed limit
		limit := determineRate(nodeLimit, userLimit) // Determine the speed limit rate
		if limit > 0 {
			limiter := rate.NewLimiter(rate.Limit(limit), int(limit)) // Byte/s
			if v, ok := inboundInfo.BucketHub.LoadOrStore(userKey, limiter); ok {
				bucket := v.(*rate.Limiter)
				return bucket, true, false
			}
			return limiter, true, false
		}
		return nil, false, false
	}

	errors.LogDebug(context.Background(), "Get Inbound Limiter information failed")
	return nil, false, false
}

// admitSlot 登记/刷新用户占用的在线名额；名额满时须有官方客户端确认才踢最旧的一个。
// 已在线的名额刷新活跃时间放行；新名额在清理过期条目后按剩余额度判定，不足则拒绝。
// 官方客户端按设备标识占名额，第三方按出口 IP 占名额，两组各自独立计数。
func admitSlot(inboundInfo *InboundInfo, userKey, ip string, uid, deviceLimit int) bool {
	clientID := 0
	if v, ok := inboundInfo.UserInfo.Load(userKey); ok {
		clientID = v.(UserInfo).ClientID
	}
	slot := OnlineKey(clientID, ip)
	now := time.Now().Unix()
	v, _ := inboundInfo.UserOnlineSlots.LoadOrStore(onlineBucket(inboundInfo.Tag, uid, clientID), new(sync.Map))
	slotMap := v.(*sync.Map)

	var grant ReclaimGrant
	if _, online := slotMap.Load(slot); online {
		slotMap.Store(slot, onlineEntry{UID: uid, LastSeen: now})
	} else {
		counter := 0
		slotMap.Range(func(key, value interface{}) bool {
			if now-value.(onlineEntry).LastSeen > int64(OnlineSlotExpiry/time.Second) {
				slotMap.Delete(key)
			} else {
				counter++
			}
			return true
		})
		if deviceLimit > 0 && counter >= deviceLimit {
			if _, ok := peekOldestOnlineSlot(slotMap, now); !ok {
				return false
			}
			grant = ConsumeReclaimGrant(uid, slot)
			if !grant.Granted {
				return false
			}
			// 用户只选了一个，名额缺口不止一个时其余继续踢最旧的
			target := grant.TargetSlot
			for deviceLimit > 0 && counter >= deviceLimit {
				evicted, ok := evictOnlineSlot(slotMap, now, target)
				if !ok {
					return false
				}
				NoteDeviceKick(uid, evicted)
				target = ""
				counter--
			}
		}
		slotMap.Store(slot, onlineEntry{UID: uid, LastSeen: now})
	}

	// 全局（跨节点）限制
	if !inboundInfo.GlobalLimit.Allow(uid, slot, deviceLimit, grant) {
		slotMap.Delete(slot)
		return false
	}
	return true
}

func peekOldestOnlineSlot(slotMap *sync.Map, now int64) (string, bool) {
	oldestSlot := ""
	oldestSeen := int64(math.MaxInt64)
	expiry := int64(OnlineSlotExpiry / time.Second)
	slotMap.Range(func(key, value interface{}) bool {
		entry := value.(onlineEntry)
		if now-entry.LastSeen > expiry {
			return true
		}
		if entry.LastSeen < oldestSeen {
			oldestSeen = entry.LastSeen
			oldestSlot = key.(string)
		}
		return true
	})
	if oldestSlot == "" {
		return "", false
	}
	return oldestSlot, true
}

// evictOnlineSlot 踢掉用户选定的 target；target 为空或已不在线时退回最旧活跃 名额。
func evictOnlineSlot(slotMap *sync.Map, now int64, target string) (string, bool) {
	victim := target
	if _, online := slotMap.Load(victim); !online {
		oldestSlot, ok := peekOldestOnlineSlot(slotMap, now)
		if !ok {
			return "", false
		}
		victim = oldestSlot
	}
	slotMap.Delete(victim)
	return victim, true
}

// EnsureOnline 供上行方向（客户端→服务端有真实数据）周期性复查：
// 名额 仍在线则刷新活跃时间；若名额已被占满且该 名额 已被挤出，
// 返回 false（调用方应断开连接）。被挤出后禁止再通过踢人重新抢回名额。
func (l *Limiter) EnsureOnline(tag, userKey, ip string) bool {
	value, ok := l.InboundInfo.Load(tag)
	if !ok {
		return true
	}
	inboundInfo := value.(*InboundInfo)

	var uid, deviceLimit, clientID int
	if v, ok := inboundInfo.UserInfo.Load(userKey); ok {
		u := v.(UserInfo)
		uid = u.UID
		deviceLimit = u.DeviceLimit
		clientID = u.ClientID
	}
	slot := OnlineKey(clientID, ip)

	v, ok := inboundInfo.UserOnlineSlots.Load(onlineBucket(tag, uid, clientID))
	if !ok {
		return false
	}
	slotMap := v.(*sync.Map)
	entryValue, online := slotMap.Load(slot)
	if !online {
		return false
	}

	now := time.Now().Unix()
	entry := entryValue.(onlineEntry)
	if now-entry.LastSeen > int64(OnlineSlotExpiry/time.Second) {
		slotMap.Delete(slot)
		return false
	}
	slotMap.Store(slot, onlineEntry{UID: uid, LastSeen: now})

	if !inboundInfo.GlobalLimit.Refresh(uid, slot, deviceLimit) {
		slotMap.Delete(slot)
		return false
	}
	return true
}

// VerifyOnline 供下行方向（远端→客户端）周期性复查：只读、不续期、不登记。
// 下行流量不能证明客户端仍然存活——客户端异常离线后，远端仍可能持续向
// 残留连接推送数据；若据此续期，离线 名额 会被无限"续命"，名额永不释放。
// 放行条件：该 名额 仍持有新鲜名额，或该用户尚有空余名额。
func (l *Limiter) VerifyOnline(tag, userKey, ip string) bool {
	value, ok := l.InboundInfo.Load(tag)
	if !ok {
		return true
	}
	inboundInfo := value.(*InboundInfo)

	var uid, deviceLimit, clientID int
	if v, ok := inboundInfo.UserInfo.Load(userKey); ok {
		u := v.(UserInfo)
		uid = u.UID
		deviceLimit = u.DeviceLimit
		clientID = u.ClientID
	}
	if deviceLimit <= 0 {
		return true
	}
	slot := OnlineKey(clientID, ip)

	v, ok := inboundInfo.UserOnlineSlots.Load(onlineBucket(tag, uid, clientID))
	if !ok {
		return true
	}
	slotMap := v.(*sync.Map)

	now := time.Now().Unix()
	fresh := 0
	selfFresh := false
	slotMap.Range(func(key, value interface{}) bool {
		if now-value.(onlineEntry).LastSeen > int64(OnlineSlotExpiry/time.Second) {
			return true
		}
		if key.(string) == slot {
			selfFresh = true
			return false
		}
		fresh++
		return true
	})
	if selfFresh {
		return true
	}
	return fresh < deviceLimit
}

// determineRate returns the minimum non-zero rate
func determineRate(nodeLimit, userLimit uint64) (limit uint64) {
	if nodeLimit == 0 || userLimit == 0 {
		if nodeLimit > userLimit {
			return nodeLimit
		} else if nodeLimit < userLimit {
			return userLimit
		} else {
			return 0
		}
	} else {
		if nodeLimit > userLimit {
			return userLimit
		} else if nodeLimit < userLimit {
			return nodeLimit
		} else {
			return nodeLimit
		}
	}
}
