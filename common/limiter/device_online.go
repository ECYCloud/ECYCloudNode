package limiter

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ECYCloud/ECYCloudNode/api"
)

func OnlineUser(uid int, slot string) api.OnlineUser {
	user := api.OnlineUser{UID: uid, ClientID: ClientIDFromOnlineKey(slot)}
	if user.ClientID == 0 {
		user.IP = slot
	}
	return user
}

const clientKeyPrefix = "client-"

// OnlineKey 是占名额的标识。官方客户端按设备计名额，标识与出口 IP 无关，
// 换网络、换协议、跨节点都不会多占；第三方仍按出口 IP 计名额。
func OnlineKey(clientID int, ip string) string {
	if clientID != 0 {
		return clientKeyPrefix + strconv.Itoa(clientID)
	}
	return ip
}

// IsClientOnlineKey 判断名额标识是否属于官方客户端
func IsClientOnlineKey(key string) bool {
	return strings.HasPrefix(key, clientKeyPrefix)
}

// ClientIDFromOnlineKey 从名额标识反解设备 ID，第三方标识返回 0
func ClientIDFromOnlineKey(key string) int {
	if !IsClientOnlineKey(key) {
		return 0
	}
	id, err := strconv.Atoi(key[len(clientKeyPrefix):])
	if err != nil {
		return 0
	}
	return id
}

// DeviceSlots 是一个账号在本节点的在线名额账本：占用中的标识集合与各自的最后活跃时间。
type DeviceSlots struct {
	Slots  map[string]struct{}
	Active map[string]time.Time
}

// ShareAccountSlots 让同一账号的官方设备共用一份名额账本。官方客户端每台设备各有
// 独立认证凭据，若各记一本就数不出「该账号几台在线」；第三方仍按认证凭据各自独立，
// 与官方分开记账，两组各自使用同一个上限。
// authKeys 为该设备的全部认证键，slots / active 是服务侧按认证键存的两张总表。
func ShareAccountSlots(shared map[int]DeviceSlots, uid, clientID int, authKeys []string,
	slots map[string]map[string]struct{}, active map[string]map[string]time.Time) {
	if clientID == 0 {
		return
	}
	book, ok := shared[uid]
	if !ok {
		// 复用该账号已在线设备的账本，否则热重载用户列表会清掉在线名额
		for _, k := range authKeys {
			if k == "" {
				continue
			}
			if book.Slots == nil {
				book.Slots = slots[k]
			}
			if book.Active == nil {
				book.Active = active[k]
			}
		}
		if book.Slots == nil {
			book.Slots = make(map[string]struct{})
		}
		if book.Active == nil {
			book.Active = make(map[string]time.Time)
		}
		shared[uid] = book
	}
	for _, k := range authKeys {
		if k == "" {
			continue
		}
		slots[k] = book.Slots
		active[k] = book.Active
	}
}

// PurgeStaleDeviceSlots 清理超过 expiry 未活跃的 名额，返回剩余活跃 名额 数。
func PurgeStaleDeviceSlots(onlineSlots map[string]struct{}, activeMap map[string]time.Time, expiry time.Duration) int {
	now := time.Now()
	fresh := 0
	for slot, last := range activeMap {
		if now.Sub(last) > expiry {
			delete(activeMap, slot)
			if onlineSlots != nil {
				delete(onlineSlots, slot)
			}
		} else {
			fresh++
		}
	}
	return fresh
}

// AdmitDeviceSlot 在协议侧本地在线表登记 名额；名额满时须有官方客户端确认才踢人，
// 优先踢用户在客户端选定的那个 名额。
// 调用方须持 mu 进入，返回时仍持 mu：取确认是一次对面板的 HTTP 调用，不能持锁等待，
// 这里会解锁去取、取回后重新加锁并重数一遍再踢。
// 第二个返回值是本次消耗到的确认，供全局限制复用，避免再查一次授权。
func AdmitDeviceSlot(mu sync.Locker, onlineSlots map[string]struct{}, activeMap map[string]time.Time, slot string, uid, deviceLimit int) (allowed bool, grant ReclaimGrant) {
	if slot == "" {
		return false, grant
	}
	for {
		fresh := PurgeStaleDeviceSlots(onlineSlots, activeMap, OnlineSlotExpiry)
		if _, exists := onlineSlots[slot]; exists {
			activeMap[slot] = time.Now()
			return true, grant
		}
		if deviceLimit > 0 && fresh >= deviceLimit {
			if _, ok := peekOldestDeviceSlot(activeMap); !ok {
				return false, grant
			}
			if !grant.Granted {
				mu.Unlock()
				grant = ConsumeReclaimGrant(uid, slot)
				mu.Lock()
				if !grant.Granted {
					return false, grant
				}
				continue
			}
			// 用户只选了一个，名额缺口不止一个时其余继续踢最旧的
			target := grant.TargetSlot
			for deviceLimit > 0 && fresh >= deviceLimit {
				evicted, ok := EvictDeviceSlot(onlineSlots, activeMap, target)
				if !ok {
					return false, grant
				}
				NoteDeviceKick(uid, evicted)
				target = ""
				fresh--
			}
		}
		onlineSlots[slot] = struct{}{}
		activeMap[slot] = time.Now()
		return true, grant
	}
}

// EnsureDeviceSlot 是协议侧上行方向（客户端→服务端有真实数据）的名额复查，与
// Limiter.EnsureOnline 同语义：slot 仍持有名额则续期并返回 online=true；闲置过期（或整张
// 表还不存在）但账号尚有空余名额时重新登记；已被挤出且名额已满返回 false，调用方
// 应断开连接。被挤出后禁止再通过踢人重新抢回名额，所以这里不消费确认、不踢人。
// onlineSlots / slotLastActive 是服务侧按认证键 key 存的两张总表，调用方须持锁。
// due 表示是否到了复查全局名额的时点，未到时调用方应跳过 Redis 往返：读写回调按每个
// 缓冲区触发，不节流会把每个包都变成一次跨节点查询。活跃时间也只在到点时刷新，否则持续
// 传输时永远到不了复查时点，全局名额会在 Expiry 后过期。
func EnsureDeviceSlot(onlineSlots map[string]map[string]struct{}, slotLastActive map[string]map[string]time.Time,
	key, slot string, deviceLimit int) (online, due bool) {
	if slot == "" {
		return false, false
	}
	now := time.Now()
	activeMap := slotLastActive[key]
	if last, ok := activeMap[slot]; ok && now.Sub(last) <= OnlineSlotExpiry {
		if now.Sub(last) < onlineTouchSec*time.Second {
			return true, false
		}
		activeMap[slot] = now
		return true, true
	}
	if !VerifyDeviceSlot(activeMap, slot, deviceLimit) {
		return false, false
	}
	if activeMap == nil {
		activeMap = make(map[string]time.Time)
		slotLastActive[key] = activeMap
	}
	slots := onlineSlots[key]
	if slots == nil {
		slots = make(map[string]struct{})
		onlineSlots[key] = slots
	}
	slots[slot] = struct{}{}
	activeMap[slot] = now
	return true, true
}

// VerifyDeviceSlot 是协议侧下行方向（远端→客户端）的名额复查，与 Limiter.VerifyOnline
// 同语义：只读、不续期。下行流量不能证明客户端仍然存活——客户端异常离线后，远端仍
// 可能持续向残留连接推送数据；若据此续期，离线名额会被无限"续命"、永不释放。
// 放行条件：该 slot 仍持有新鲜名额，或该用户尚有空余名额。
func VerifyDeviceSlot(activeMap map[string]time.Time, slot string, deviceLimit int) bool {
	if deviceLimit <= 0 {
		return true
	}
	now := time.Now()
	fresh := 0
	for key, last := range activeMap {
		if now.Sub(last) > OnlineSlotExpiry {
			continue
		}
		if key == slot {
			return true
		}
		fresh++
	}
	return fresh < deviceLimit
}
