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
	// OnlineIPExpiry IP 无活动超过该时长即视为下线，释放设备名额
	OnlineIPExpiry = time.Minute
	// onlineTouchSec 存活连接刷新在线状态/复查名额的间隔（秒）
	onlineTouchSec = 10
)

type UserInfo struct {
	UID         int
	SpeedLimit  uint64
	DeviceLimit int
}

// onlineEntry 记录单个在线 IP 的归属与最近活跃时间（unix 秒）
type onlineEntry struct {
	UID      int
	LastSeen int64
}

type InboundInfo struct {
	Tag            string
	NodeSpeedLimit uint64
	UserInfo       *sync.Map // Key: user identifier (usually UID string) -> UserInfo
	BucketHub      *sync.Map // Key: user identifier -> *rate.Limiter
	UserOnlineIP   *sync.Map // Key: user identifier -> *sync.Map (Key: IP, Value: onlineEntry)
	GlobalLimit    *GlobalDeviceChecker
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
		Tag:            tag,
		NodeSpeedLimit: nodeSpeedLimit,
		BucketHub:      new(sync.Map),
		UserOnlineIP:   new(sync.Map),
		GlobalLimit:    NewGlobalDeviceChecker(globalLimit),
	}

	userMap := new(sync.Map)
	for _, u := range *userList {
		// Use tag|UID format to match buildUserTag() in controller
		// This ensures consistent key format across limiter and traffic counter
		userKey := fmt.Sprintf("%s|%d", tag, u.UID)
		userMap.Store(userKey, UserInfo{
			UID:         u.UID,
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
			// Use tag|UID format to match buildUserTag() in controller
			// This ensures consistent key format across limiter and traffic counter
			userKey := fmt.Sprintf("%s|%d", tag, u.UID)
			inboundInfo.UserInfo.Store(userKey, UserInfo{
				UID:         u.UID,
				SpeedLimit:  u.SpeedLimit,
				DeviceLimit: u.DeviceLimit,
			})
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
		// 只清理过期 IP，保留活跃 IP 的在线状态。
		// 整表清空会导致每个上报周期设备名额被重新抢占，使设备限制形同虚设。
		inboundInfo.UserOnlineIP.Range(func(key, value interface{}) bool {
			email := key.(string)
			ipMap := value.(*sync.Map)
			active := 0
			ipMap.Range(func(ipKey, entryValue interface{}) bool {
				entry := entryValue.(onlineEntry)
				if now-entry.LastSeen > int64(OnlineIPExpiry/time.Second) {
					ipMap.Delete(ipKey)
					return true
				}
				active++
				onlineUser = append(onlineUser, api.OnlineUser{UID: entry.UID, IP: ipKey.(string)})
				return true
			})
			if active == 0 {
				// 用户已完全下线：释放在线表与限速桶
				inboundInfo.UserOnlineIP.Delete(email)
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
			userLimit        uint64
			deviceLimit, uid int
		)

		inboundInfo := value.(*InboundInfo)
		nodeLimit := inboundInfo.NodeSpeedLimit

		if v, ok := inboundInfo.UserInfo.Load(userKey); ok {
			u := v.(UserInfo)
			uid = u.UID
			userLimit = u.SpeedLimit
			deviceLimit = u.DeviceLimit
		}

		// Local + global device limit (registers the IP as online on success)
		if !admitIP(inboundInfo, userKey, ip, uid, deviceLimit) {
			return nil, false, true
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

// admitIP 登记/刷新用户的在线 IP；名额满时须有官方客户端确认才踢最旧 IP。
// 已在线 IP 刷新活跃时间放行；新 IP 在清理过期条目后按剩余名额判定，不足则拒绝。
func admitIP(inboundInfo *InboundInfo, userKey, ip string, uid, deviceLimit int) bool {
	now := time.Now().Unix()
	v, _ := inboundInfo.UserOnlineIP.LoadOrStore(userKey, new(sync.Map))
	ipMap := v.(*sync.Map)

	var grant ReclaimGrant
	if _, online := ipMap.Load(ip); online {
		ipMap.Store(ip, onlineEntry{UID: uid, LastSeen: now})
	} else {
		counter := 0
		ipMap.Range(func(key, value interface{}) bool {
			if now-value.(onlineEntry).LastSeen > int64(OnlineIPExpiry/time.Second) {
				ipMap.Delete(key)
			} else {
				counter++
			}
			return true
		})
		if deviceLimit > 0 && counter >= deviceLimit {
			if _, ok := peekOldestOnlineIP(ipMap, now); !ok {
				return false
			}
			grant = ConsumeReclaimGrant(uid, ip)
			if !grant.Granted {
				return false
			}
			// 用户只选了一个，名额缺口不止一个时其余继续踢最旧的
			target := grant.TargetIP
			for deviceLimit > 0 && counter >= deviceLimit {
				evicted, ok := evictOnlineIP(ipMap, now, target)
				if !ok {
					return false
				}
				NoteDeviceKick(uid, evicted)
				target = ""
				counter--
			}
		}
		ipMap.Store(ip, onlineEntry{UID: uid, LastSeen: now})
	}

	// 全局（跨节点）限制
	if !inboundInfo.GlobalLimit.Allow(uid, ip, deviceLimit, grant) {
		ipMap.Delete(ip)
		return false
	}
	return true
}

func peekOldestOnlineIP(ipMap *sync.Map, now int64) (string, bool) {
	oldestIP := ""
	oldestSeen := int64(math.MaxInt64)
	expiry := int64(OnlineIPExpiry / time.Second)
	ipMap.Range(func(key, value interface{}) bool {
		entry := value.(onlineEntry)
		if now-entry.LastSeen > expiry {
			return true
		}
		if entry.LastSeen < oldestSeen {
			oldestSeen = entry.LastSeen
			oldestIP = key.(string)
		}
		return true
	})
	if oldestIP == "" {
		return "", false
	}
	return oldestIP, true
}

// evictOnlineIP 踢掉用户选定的 target；target 为空或已不在线时退回最旧活跃 IP。
func evictOnlineIP(ipMap *sync.Map, now int64, target string) (string, bool) {
	victim := target
	if _, online := ipMap.Load(victim); !online {
		oldestIP, ok := peekOldestOnlineIP(ipMap, now)
		if !ok {
			return "", false
		}
		victim = oldestIP
	}
	ipMap.Delete(victim)
	return victim, true
}

// EnsureOnline 供上行方向（客户端→服务端有真实数据）周期性复查：
// IP 仍在线则刷新活跃时间；若名额已被占满且该 IP 已被挤出，
// 返回 false（调用方应断开连接）。被挤出后禁止再通过踢人重新抢回名额。
func (l *Limiter) EnsureOnline(tag, userKey, ip string) bool {
	value, ok := l.InboundInfo.Load(tag)
	if !ok {
		return true
	}
	inboundInfo := value.(*InboundInfo)

	var uid, deviceLimit int
	if v, ok := inboundInfo.UserInfo.Load(userKey); ok {
		u := v.(UserInfo)
		uid = u.UID
		deviceLimit = u.DeviceLimit
	}

	v, ok := inboundInfo.UserOnlineIP.Load(userKey)
	if !ok {
		return false
	}
	ipMap := v.(*sync.Map)
	entryValue, online := ipMap.Load(ip)
	if !online {
		return false
	}

	now := time.Now().Unix()
	entry := entryValue.(onlineEntry)
	if now-entry.LastSeen > int64(OnlineIPExpiry/time.Second) {
		ipMap.Delete(ip)
		return false
	}
	ipMap.Store(ip, onlineEntry{UID: uid, LastSeen: now})

	if !inboundInfo.GlobalLimit.Refresh(uid, ip, deviceLimit) {
		ipMap.Delete(ip)
		return false
	}
	return true
}

// VerifyOnline 供下行方向（远端→客户端）周期性复查：只读、不续期、不登记。
// 下行流量不能证明客户端仍然存活——客户端异常离线后，远端仍可能持续向
// 残留连接推送数据；若据此续期，离线 IP 会被无限"续命"，名额永不释放。
// 放行条件：该 IP 仍持有新鲜名额，或该用户尚有空余名额。
func (l *Limiter) VerifyOnline(tag, userKey, ip string) bool {
	value, ok := l.InboundInfo.Load(tag)
	if !ok {
		return true
	}
	inboundInfo := value.(*InboundInfo)

	var deviceLimit int
	if v, ok := inboundInfo.UserInfo.Load(userKey); ok {
		deviceLimit = v.(UserInfo).DeviceLimit
	}
	if deviceLimit <= 0 {
		return true
	}

	v, ok := inboundInfo.UserOnlineIP.Load(userKey)
	if !ok {
		return true
	}
	ipMap := v.(*sync.Map)

	now := time.Now().Unix()
	fresh := 0
	selfFresh := false
	ipMap.Range(func(key, value interface{}) bool {
		if now-value.(onlineEntry).LastSeen > int64(OnlineIPExpiry/time.Second) {
			return true
		}
		if key.(string) == ip {
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
