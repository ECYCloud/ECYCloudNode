package limiter

import (
	"fmt"
	"sync"
	"time"

	"github.com/ECYCloud/ECYCloudNode/api"
)

var deviceKickBuffer sync.Map // key: "uid|ip" -> api.OnlineUser

// NoteDeviceKick 记录因在线 IP 超限被挤出的 IP，供上报面板后通知官方客户端。
func NoteDeviceKick(uid int, ip string) {
	if uid <= 0 || ip == "" {
		return
	}
	deviceKickBuffer.Store(fmt.Sprintf("%d|%s", uid, ip), api.OnlineUser{UID: uid, IP: ip})
}

// TakeDeviceKicks 取出并清空待上报的踢下线记录。
func TakeDeviceKicks() []api.OnlineUser {
	var out []api.OnlineUser
	deviceKickBuffer.Range(func(key, value interface{}) bool {
		out = append(out, value.(api.OnlineUser))
		deviceKickBuffer.Delete(key)
		return true
	})
	return out
}

func peekOldestDeviceIP(activeMap map[string]time.Time) (string, bool) {
	if len(activeMap) == 0 {
		return "", false
	}
	oldestIP := ""
	var oldestAt time.Time
	first := true
	for ip, at := range activeMap {
		if first || at.Before(oldestAt) {
			oldestIP = ip
			oldestAt = at
			first = false
		}
	}
	if oldestIP == "" {
		return "", false
	}
	return oldestIP, true
}

// EvictOldestDeviceIP 从 activeMap 中移除最旧活跃 IP，同步清理 onlineIPs，返回被踢 IP。
func EvictOldestDeviceIP(onlineIPs map[string]struct{}, activeMap map[string]time.Time) (string, bool) {
	oldestIP, ok := peekOldestDeviceIP(activeMap)
	if !ok {
		return "", false
	}
	delete(activeMap, oldestIP)
	if onlineIPs != nil {
		delete(onlineIPs, oldestIP)
	}
	return oldestIP, true
}
