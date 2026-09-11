package limiter

import (
	"strconv"
	"strings"
	"time"
)

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

// PurgeStaleDeviceIPs 清理超过 expiry 未活跃的 IP，返回剩余活跃 IP 数。
func PurgeStaleDeviceIPs(onlineIPs map[string]struct{}, activeMap map[string]time.Time, expiry time.Duration) int {
	now := time.Now()
	fresh := 0
	for ip, last := range activeMap {
		if now.Sub(last) > expiry {
			delete(activeMap, ip)
			if onlineIPs != nil {
				delete(onlineIPs, ip)
			}
		} else {
			fresh++
		}
	}
	return fresh
}

// AdmitDeviceIP 在协议侧本地在线表登记 IP；名额满时须有官方客户端确认才踢人，
// 优先踢用户在客户端选定的那个 IP。
// 第二个返回值是本次消耗到的确认，供全局限制复用，避免再查一次授权。
func AdmitDeviceIP(onlineIPs map[string]struct{}, activeMap map[string]time.Time, ip string, uid, deviceLimit int) (allowed bool, grant ReclaimGrant) {
	if ip == "" {
		return false, grant
	}
	fresh := PurgeStaleDeviceIPs(onlineIPs, activeMap, OnlineIPExpiry)
	if _, exists := onlineIPs[ip]; exists {
		activeMap[ip] = time.Now()
		return true, grant
	}
	if deviceLimit > 0 && fresh >= deviceLimit {
		if _, ok := peekOldestDeviceIP(activeMap); !ok {
			return false, grant
		}
		grant = ConsumeReclaimGrant(uid, ip)
		if !grant.Granted {
			return false, grant
		}
		// 用户只选了一个，名额缺口不止一个时其余继续踢最旧的
		target := grant.TargetIP
		for deviceLimit > 0 && fresh >= deviceLimit {
			evicted, ok := EvictDeviceIP(onlineIPs, activeMap, target)
			if !ok {
				return false, grant
			}
			NoteDeviceKick(uid, evicted)
			target = ""
			fresh--
		}
	}
	onlineIPs[ip] = struct{}{}
	activeMap[ip] = time.Now()
	return true, grant
}
