package limiter

import (
	"net"
	"strings"
)

// ReclaimGrant 是官方客户端的挤下线确认。TargetIP 为用户在客户端选定要挤下线的 IP，
// 为空（旧版客户端或该 IP 已下线）时由节点挑最旧活跃 IP。
type ReclaimGrant struct {
	Granted  bool
	TargetIP string
}

var reclaimConsumer func(int, string) (bool, string)

func SetReclaimConsumer(fn func(int, string) (bool, string)) {
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

func ConsumeReclaimGrant(uid int, ip string) ReclaimGrant {
	ip = NormalizeClientIP(ip)
	if uid <= 0 || ip == "" || reclaimConsumer == nil {
		return ReclaimGrant{}
	}
	ok, targetIP := reclaimConsumer(uid, ip)
	if !ok {
		return ReclaimGrant{}
	}
	return ReclaimGrant{Granted: true, TargetIP: NormalizeClientIP(targetIP)}
}
