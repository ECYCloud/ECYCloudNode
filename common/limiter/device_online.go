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
