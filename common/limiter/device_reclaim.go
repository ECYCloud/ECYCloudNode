package limiter

import (
	"net"
	"strings"
)

var reclaimConsumer func(int, string) bool

func SetReclaimConsumer(fn func(int, string) bool) {
	reclaimConsumer = fn
}

func NormalizeClientIP(ip string) string {
	ip = strings.TrimSpace(strings.TrimPrefix(ip, "::ffff:"))
	if i := strings.IndexByte(ip, ','); i >= 0 {
		ip = strings.TrimSpace(strings.TrimPrefix(ip[:i], "::ffff:"))
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.String()
	}
	return parsed.String()
}

func ConsumeReclaimGrant(uid int, ip string) bool {
	ip = NormalizeClientIP(ip)
	if uid <= 0 || ip == "" || reclaimConsumer == nil {
		return false
	}
	return reclaimConsumer(uid, ip)
}
