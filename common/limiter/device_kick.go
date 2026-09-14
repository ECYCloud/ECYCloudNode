package limiter

import (
	"fmt"
	"sync"
	"time"

	"github.com/ECYCloud/ECYCloudNode/api"
)

var deviceKickBuffer sync.Map // key: "uid|slot" -> api.OnlineUser

// NoteDeviceKick 记录因在线 名额 超限被挤出的 名额，供上报面板后通知官方客户端。
func NoteDeviceKick(uid int, slot string) {
	if uid <= 0 || slot == "" {
		return
	}
	deviceKickBuffer.Store(fmt.Sprintf("%d|%s", uid, slot), OnlineUser(uid, slot))
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

func peekOldestDeviceSlot(activeMap map[string]time.Time) (string, bool) {
	if len(activeMap) == 0 {
		return "", false
	}
	oldestSlot := ""
	var oldestAt time.Time
	first := true
	for slot, at := range activeMap {
		if first || at.Before(oldestAt) {
			oldestSlot = slot
			oldestAt = at
			first = false
		}
	}
	if oldestSlot == "" {
		return "", false
	}
	return oldestSlot, true
}

// EvictDeviceSlot 移除用户选定的 target，同步清理 onlineSlots，返回被踢 名额。
// target 为空或已不在线时退回最旧活跃 名额。
func EvictDeviceSlot(onlineSlots map[string]struct{}, activeMap map[string]time.Time, target string) (string, bool) {
	victim := target
	if _, online := activeMap[victim]; !online {
		oldestSlot, ok := peekOldestDeviceSlot(activeMap)
		if !ok {
			return "", false
		}
		victim = oldestSlot
	}
	delete(activeMap, victim)
	if onlineSlots != nil {
		delete(onlineSlots, victim)
	}
	return victim, true
}
