package limiter

import (
	"net"
	"strings"
)

type ReclaimGrant struct {
	Granted    bool
	TargetSlot string
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

func ConsumeReclaimGrant(uid int, slot string) ReclaimGrant {
	slot = strings.TrimSpace(slot)
	if !IsClientOnlineKey(slot) {
		slot = NormalizeClientIP(slot)
	}
	if uid <= 0 || slot == "" || reclaimConsumer == nil {
		return ReclaimGrant{}
	}
	ok, targetSlot := reclaimConsumer(uid, slot)
	if !ok {
		return ReclaimGrant{}
	}
	targetSlot = strings.TrimSpace(targetSlot)
	if !IsClientOnlineKey(targetSlot) {
		targetSlot = NormalizeClientIP(targetSlot)
	}
	return ReclaimGrant{Granted: true, TargetSlot: targetSlot}
}
