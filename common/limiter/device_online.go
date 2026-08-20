package limiter

import "time"

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
