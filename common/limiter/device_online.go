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

// AdmitDeviceIP 在协议侧本地在线表登记 IP；名额满时须有官方客户端确认才踢最旧活跃 IP。
// 第二个返回值表示本次已消耗确认，供全局限制复用，避免再查一次授权。
func AdmitDeviceIP(onlineIPs map[string]struct{}, activeMap map[string]time.Time, ip string, uid, deviceLimit int) (allowed bool, granted bool) {
	if ip == "" {
		return false, false
	}
	fresh := PurgeStaleDeviceIPs(onlineIPs, activeMap, OnlineIPExpiry)
	if _, exists := onlineIPs[ip]; exists {
		activeMap[ip] = time.Now()
		return true, false
	}
	if deviceLimit > 0 && fresh >= deviceLimit {
		if _, ok := peekOldestDeviceIP(activeMap); !ok {
			return false, false
		}
		if !ConsumeReclaimGrant(uid, ip) {
			return false, false
		}
		granted = true
		for deviceLimit > 0 && fresh >= deviceLimit {
			evicted, ok := EvictOldestDeviceIP(onlineIPs, activeMap)
			if !ok {
				return false, false
			}
			NoteDeviceKick(uid, evicted)
			fresh--
		}
	}
	onlineIPs[ip] = struct{}{}
	activeMap[ip] = time.Now()
	return true, granted
}
