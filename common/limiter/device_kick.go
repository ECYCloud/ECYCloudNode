package limiter

import (
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/ECYCloud/ECYCloudNode/api"
)

type deviceKick struct {
	tag  string
	user api.OnlineUser
}

var deviceKickBuffer sync.Map // key: "tag|uid|slot" -> deviceKick

// NoteDeviceKick 记录 tag 节点因在线 名额 超限挤出的 名额，供该节点上报面板后通知官方客户端。
func NoteDeviceKick(tag string, uid int, slot string) {
	if uid <= 0 || slot == "" {
		return
	}
	deviceKickBuffer.Store(fmt.Sprintf("%s|%d|%s", tag, uid, slot), deviceKick{tag: tag, user: OnlineUser(uid, slot)})
}

// TakeDeviceKicks 取出并清空 tags 节点（不传时为全部节点）待上报的踢下线记录。
// 面板按上报节点校验用户归属，每个节点只报自己的记录。
func TakeDeviceKicks(tags ...string) []api.OnlineUser {
	var out []api.OnlineUser
	deviceKickBuffer.Range(func(key, value interface{}) bool {
		kick := value.(deviceKick)
		if len(tags) == 0 || slices.Contains(tags, kick.tag) {
			out = append(out, kick.user)
			deviceKickBuffer.Delete(key)
		}
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
