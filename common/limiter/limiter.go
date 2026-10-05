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
	ValidUntil  int64
	KickVersion uint64
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
	RecordTraffic   func(int, int64, int64) error
	// slotMu 串行化在线账本的「先数后写」：sync.Map 只保证单次操作原子，
	// 两条连接同时数到「未满」再各自登记就会超限
	slotMu sync.Mutex
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

func (l *Limiter) AddInboundLimiter(tag string, nodeSpeedLimit uint64, userList *[]api.UserInfo, globalLimit *GlobalDeviceLimitConfig, recorder ...func(int, int64, int64) error) error {
	inboundInfo := &InboundInfo{
		Tag:             tag,
		NodeSpeedLimit:  nodeSpeedLimit,
		BucketHub:       new(sync.Map),
		UserOnlineSlots: new(sync.Map),
		GlobalLimit:     NewGlobalDeviceChecker(globalLimit),
	}
	if len(recorder) > 0 {
		inboundInfo.RecordTraffic = recorder[0]
	}

	userMap := new(sync.Map)
	for _, u := range *userList {
		userKey := u.Key(tag)
		userMap.Store(userKey, UserInfo{
			ValidUntil:  u.ValidUntil,
			KickVersion: u.KickVersion,
			UID:         u.UID,
			ClientID:    u.ClientID,
			SpeedLimit:  u.SpeedLimit,
			DeviceLimit: u.DeviceLimit,
		})
	}
	inboundInfo.UserInfo = userMap
	inboundInfo.GlobalLimit.SyncUsers(userList)
	l.InboundInfo.Store(tag, inboundInfo) // Replace the old inbound info
	return nil
}

func (l *Limiter) TrafficRecorder(tag, userKey string) func(int64, int64) error {
	value, ok := l.InboundInfo.Load(tag)
	if !ok {
		return nil
	}
	info := value.(*InboundInfo)
	if info.RecordTraffic == nil {
		return nil
	}
	user, ok := info.UserInfo.Load(userKey)
	if !ok {
		return func(int64, int64) error { return fmt.Errorf("traffic account is no longer authorized") }
	}
	uid := user.(UserInfo).UID
	return func(up, down int64) error { return info.RecordTraffic(uid, up, down) }
}

func (l *Limiter) UpdateInboundLimiter(tag string, updatedUserList *[]api.UserInfo, replace ...bool) error {
	if value, ok := l.InboundInfo.Load(tag); ok {
		inboundInfo := value.(*InboundInfo)
		inboundInfo.slotMu.Lock()
		if len(replace) > 0 && replace[0] {
			keys := make(map[string]bool, len(*updatedUserList))
			for _, user := range *updatedUserList {
				keys[user.Key(tag)] = true
			}
			inboundInfo.UserInfo.Range(func(key, value any) bool {
				if !keys[key.(string)] {
					inboundInfo.UserInfo.Delete(key)
				}
				return true
			})
		}
		// Update User info
		for _, u := range *updatedUserList {
			userKey := u.Key(tag)
			kickVersion := u.KickVersion
			if old, ok := inboundInfo.UserInfo.Load(userKey); ok {
				kickVersion = max(kickVersion, old.(UserInfo).KickVersion)
				if old.(UserInfo).KickVersion != kickVersion {
					if slots, ok := inboundInfo.UserOnlineSlots.Load(onlineBucket(tag, u.UID, u.ClientID)); ok {
						slots.(*sync.Map).Delete(OnlineKey(u.ClientID, ""))
					}
				}
			}
			inboundInfo.UserInfo.Store(userKey, UserInfo{
				ValidUntil:  u.ValidUntil,
				KickVersion: kickVersion,
				UID:         u.UID,
				ClientID:    u.ClientID,
				SpeedLimit:  u.SpeedLimit,
				DeviceLimit: u.DeviceLimit,
			})
			inboundInfo.updateRateBucket(userKey, u.UID, u.ClientID, u.SpeedLimit)
		}
		inboundInfo.slotMu.Unlock()
		inboundInfo.GlobalLimit.SyncUsers(updatedUserList)
	} else {
		return fmt.Errorf("no such inbound in limiter: %s", tag)
	}
	return nil
}

func (l *Limiter) UpdateInboundSpeedLimit(tag string, users *[]api.UserInfo) error {
	value, ok := l.InboundInfo.Load(tag)
	if !ok {
		return fmt.Errorf("no such inbound in limiter: %s", tag)
	}
	info := value.(*InboundInfo)
	info.slotMu.Lock()
	defer info.slotMu.Unlock()
	for _, update := range *users {
		key := update.Key(tag)
		value, ok := info.UserInfo.Load(key)
		if !ok {
			continue
		}
		user := value.(UserInfo)
		user.SpeedLimit = update.SpeedLimit
		info.UserInfo.Store(key, user)
		info.updateRateBucket(key, user.UID, user.ClientID, user.SpeedLimit)
	}
	return nil
}

func (info *InboundInfo) updateRateBucket(key string, uid, clientID int, speed uint64) {
	if clientID != 0 {
		key = fmt.Sprintf("%s|%d", info.Tag, uid)
	}
	limit := determineRate(info.NodeSpeedLimit, speed)
	if limit == 0 {
		info.BucketHub.Delete(key)
	} else if bucket, ok := info.BucketHub.Load(key); ok {
		lim := bucket.(*rate.Limiter)
		lim.SetLimit(rate.Limit(limit))
		lim.SetBurst(int(limit))
	}
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
		inboundInfo.slotMu.Lock()
		defer inboundInfo.slotMu.Unlock()
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
	if !l.AuthorizationAllowed(tag, userKey) {
		return nil, false, true
	}
	if value, ok := l.InboundInfo.Load(tag); ok {
		var (
			deviceLimit, uid int
		)

		inboundInfo := value.(*InboundInfo)
		if v, ok := inboundInfo.UserInfo.Load(userKey); ok {
			u := v.(UserInfo)
			uid = u.UID
			deviceLimit = u.DeviceLimit
		}

		if !admitSlot(inboundInfo, userKey, ip, uid, deviceLimit) {
			return nil, false, true
		}

		limiter = l.rateBucket(tag, userKey)
		return limiter, limiter != nil, false
	}

	errors.LogDebug(context.Background(), "Get Inbound Limiter information failed")
	return nil, false, false
}

func (l *Limiter) rateBucket(tag, userKey string) *rate.Limiter {
	value, ok := l.InboundInfo.Load(tag)
	if !ok {
		return nil
	}
	inboundInfo := value.(*InboundInfo)
	value, ok = inboundInfo.UserInfo.Load(userKey)
	if !ok {
		return nil
	}
	u := value.(UserInfo)
	limit := determineRate(inboundInfo.NodeSpeedLimit, u.SpeedLimit)
	if limit == 0 {
		return nil
	}
	if u.ClientID != 0 {
		userKey = fmt.Sprintf("%s|%d", tag, u.UID)
	}
	if value, ok := inboundInfo.BucketHub.Load(userKey); ok {
		return value.(*rate.Limiter)
	}
	bucket := rate.NewLimiter(rate.Limit(limit), int(limit))
	value, _ = inboundInfo.BucketHub.LoadOrStore(userKey, bucket)
	return value.(*rate.Limiter)
}

// admitSlot 登记/刷新用户占用的在线名额；名额满时须有官方客户端确认才踢最旧的一个。
// 已在线的名额刷新活跃时间放行；新名额在清理过期条目后按剩余额度判定，不足则拒绝。
// 官方客户端按设备标识占名额，第三方按出口 IP 占名额，两组各自独立计数。
func admitSlot(inboundInfo *InboundInfo, userKey, ip string, uid, deviceLimit int) bool {
	clientID := 0
	user := UserInfo{}
	if v, ok := inboundInfo.UserInfo.Load(userKey); ok {
		user = v.(UserInfo)
		clientID = user.ClientID
	}
	slot := OnlineKey(clientID, ip)
	bucket := onlineBucket(inboundInfo.Tag, uid, clientID)

	var (
		grant   ReclaimGrant
		slotMap *sync.Map
	)
	inboundInfo.slotMu.Lock()
	for {
		now := time.Now().Unix()
		v, _ := inboundInfo.UserOnlineSlots.LoadOrStore(bucket, new(sync.Map))
		slotMap = v.(*sync.Map)
		if _, online := slotMap.Load(slot); online {
			slotMap.Store(slot, onlineEntry{UID: uid, LastSeen: now})
			break
		}
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
				inboundInfo.slotMu.Unlock()
				return false
			}
			if !grant.Granted {
				// 取确认是一次对面板的 HTTP 调用，不能持锁等待；拿到后重新数一遍再踢
				inboundInfo.slotMu.Unlock()
				if grant = ConsumeReclaimGrant(uid, slot); !grant.Granted {
					return false
				}
				inboundInfo.slotMu.Lock()
				continue
			}
			// 用户只选了一个，名额缺口不止一个时其余继续踢最旧的
			target := grant.TargetSlot
			for deviceLimit > 0 && counter >= deviceLimit {
				evicted, ok := evictOnlineSlot(slotMap, now, target)
				if !ok {
					inboundInfo.slotMu.Unlock()
					return false
				}
				NoteDeviceKick(uid, evicted)
				target = ""
				counter--
			}
		}
		slotMap.Store(slot, onlineEntry{UID: uid, LastSeen: now})
		break
	}
	inboundInfo.slotMu.Unlock()

	// 全局（跨节点）限制
	if !inboundInfo.GlobalLimit.Allow(uid, slot, deviceLimit, grant, user) {
		inboundInfo.releaseRejectedSlot(userKey, slot, slotMap, user.KickVersion)
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
// 名额 仍在线则刷新活跃时间，闲置过期但账号尚有空余名额时重新登记；若名额已被占满且该 名额 已被挤出，
// 返回 false（调用方应断开连接）。被挤出后禁止再通过踢人重新抢回名额。
func (l *Limiter) EnsureOnline(tag, userKey, ip string) bool {
	if !l.AuthorizationAllowed(tag, userKey) {
		return false
	}
	value, ok := l.InboundInfo.Load(tag)
	if !ok {
		return true
	}
	inboundInfo := value.(*InboundInfo)

	var uid, deviceLimit, clientID int
	var user UserInfo
	if v, ok := inboundInfo.UserInfo.Load(userKey); ok {
		u := v.(UserInfo)
		user = u
		uid = u.UID
		deviceLimit = u.DeviceLimit
		clientID = u.ClientID
	}
	slot := OnlineKey(clientID, ip)

	inboundInfo.slotMu.Lock()
	if !l.VerifyOnline(tag, userKey, ip) {
		inboundInfo.slotMu.Unlock()
		return false
	}
	v, _ := inboundInfo.UserOnlineSlots.LoadOrStore(onlineBucket(tag, uid, clientID), new(sync.Map))
	slotMap := v.(*sync.Map)
	slotMap.Store(slot, onlineEntry{UID: uid, LastSeen: time.Now().Unix()})
	inboundInfo.slotMu.Unlock()

	if !inboundInfo.GlobalLimit.Refresh(uid, slot, deviceLimit, user) {
		inboundInfo.releaseRejectedSlot(userKey, slot, slotMap, user.KickVersion)
		return false
	}
	return true
}

func (info *InboundInfo) releaseRejectedSlot(userKey, slot string, slots *sync.Map, version uint64) {
	info.slotMu.Lock()
	defer info.slotMu.Unlock()
	if user, ok := info.UserInfo.Load(userKey); ok && user.(UserInfo).KickVersion == version {
		slots.Delete(slot)
	}
}

// VerifyOnline 供下行方向（远端→客户端）周期性复查：只读、不续期、不登记。
// 下行流量不能证明客户端仍然存活——客户端异常离线后，远端仍可能持续向
// 残留连接推送数据；若据此续期，离线 名额 会被无限"续命"，名额永不释放。
// 放行条件：该 名额 仍持有新鲜名额，或该用户尚有空余名额。
func (l *Limiter) VerifyOnline(tag, userKey, ip string) bool {
	if !l.AuthorizationAllowed(tag, userKey) {
		return false
	}
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

func (l *Limiter) KickVersion(tag, userKey string) uint64 {
	if value, ok := l.InboundInfo.Load(tag); ok {
		if user, ok := value.(*InboundInfo).UserInfo.Load(userKey); ok {
			return user.(UserInfo).KickVersion
		}
	}
	return 0
}

func (l *Limiter) AuthorizationAllowed(tag, userKey string, version ...uint64) bool {
	value, ok := l.InboundInfo.Load(tag)
	if !ok {
		return false
	}
	inbound := value.(*InboundInfo)
	value, ok = inbound.UserInfo.Load(userKey)
	if !ok {
		return false
	}
	user := value.(UserInfo)
	return (len(version) == 0 || user.KickVersion == version[0]) &&
		(user.ValidUntil == 0 || time.Now().Unix() < user.ValidUntil)
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
