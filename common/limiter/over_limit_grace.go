package limiter

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ECYCloud/ECYCloudNode/api"
)

// 第三方客户端按出口 IP 占名额，换网络后旧 IP 要闲置 OnlineSlotExpiry 才释放名额，
// 新 IP 若在名额已满时立即被拒就会误伤。名额满时给第三方新 IP 一段宽限（面板随用户
// 列表下发，单位秒）：宽限内放行但不登记进名额账本，期间有名额空出就由原有复查逻辑
// 登记转正；宽限结束仍超限则拒绝，已建立的连接在下一次复查时断开。
// 官方客户端不适用宽限，宽限为 0 时保持超限立即拒绝。
type overLimitEntry struct {
	deadline time.Time
	lastSeen time.Time
}

var overLimit = struct {
	sync.Mutex
	entries   map[string]overLimitEntry
	lastSweep time.Time
}{entries: make(map[string]overLimitEntry)}

func overLimitKey(tag string, uid int, slot string) string {
	return tag + "|" + strconv.Itoa(uid) + "|" + slot
}

// overLimitGrace 在名额已满时判断第三方 slot 是否仍在宽限内。start 为 true（新连接准入）时
// 首次超限开始计时；复查只认已有记录。记录闲置超过 OnlineSlotExpiry 即作废，再次超限重新计时；
// 宽限结束后只要该 IP 仍在尝试，记录就保留，不会重新获得宽限。
func overLimitGrace(tag string, uid int, slot string, grace int64, start bool) bool {
	if grace <= 0 || slot == "" || IsClientOnlineKey(slot) {
		return false
	}
	now := time.Now()
	key := overLimitKey(tag, uid, slot)
	overLimit.Lock()
	defer overLimit.Unlock()
	if now.Sub(overLimit.lastSweep) > OnlineSlotExpiry {
		overLimit.lastSweep = now
		for k, entry := range overLimit.entries {
			if now.Sub(entry.lastSeen) > OnlineSlotExpiry {
				delete(overLimit.entries, k)
			}
		}
	}
	entry, ok := overLimit.entries[key]
	if !ok || now.Sub(entry.lastSeen) > OnlineSlotExpiry {
		if !start {
			return false
		}
		entry.deadline = now.Add(time.Duration(grace) * time.Second)
	}
	entry.lastSeen = now
	overLimit.entries[key] = entry
	return now.Before(entry.deadline)
}

// OverLimitOnlineUsers 返回 tag 节点上仍在宽限内、近期活跃的第三方 IP，随在线名额一起上报面板，
// 否则超限期间面板看不到这些 IP。
func OverLimitOnlineUsers(tag string) []api.OnlineUser {
	now := time.Now()
	overLimit.Lock()
	defer overLimit.Unlock()
	var users []api.OnlineUser
	for key, entry := range overLimit.entries {
		rest, ok := strings.CutPrefix(key, tag+"|")
		if !ok || now.Sub(entry.lastSeen) > OnlineSlotExpiry || !now.Before(entry.deadline) {
			continue
		}
		if id, ip, ok := strings.Cut(rest, "|"); ok {
			if uid, err := strconv.Atoi(id); err == nil {
				users = append(users, api.OnlineUser{UID: uid, IP: ip})
			}
		}
	}
	return users
}
