package limiter

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"

	"github.com/ECYCloud/ECYCloudNode/api"
)

type ReclaimGrant struct {
	Granted    bool
	TargetSlot string
}

// reclaimRetryAfter 内同一设备不再重复问面板：名额满时每条新连接都要同步等一次面板，
// 一台设备往往同时发起十几条连接，拒绝和失败都不暂留会把请求成倍放大到面板。
const reclaimRetryAfter = 3 * time.Second

type reclaimer struct {
	consume func(int, string) (bool, string)
	mu      sync.Mutex
	held    map[string]time.Time // uid|slot -> 在此之前不再询问
}

// reclaimers 按节点 tag 登记回收确认入口：多面板部署时只能问连接所属节点的面板，
// 节点启动、重建与关闭会在数据面读取的同时登记或注销。
var reclaimers sync.Map // tag -> *reclaimer

// SetReclaimConsumer 登记 tag 节点取回收确认的方法，fn 为 nil 时注销。
func SetReclaimConsumer(tag string, fn func(int, string) (bool, string)) {
	if fn == nil {
		reclaimers.Delete(tag)
		return
	}
	reclaimers.Store(tag, &reclaimer{consume: fn, held: make(map[string]time.Time)})
}

// PanelReclaim 经节点自己的面板客户端取回收确认；第三方没有回收授权入口，判满直接拒绝，不请求面板。
func PanelReclaim(client api.API) func(int, string) (bool, string) {
	return func(uid int, slot string) (bool, string) {
		if !IsClientOnlineKey(slot) {
			return false, ""
		}
		ok, targetSlot, err := client.ConsumeSlotReclaim(uid, slot)
		if err != nil {
			errors.LogWarning(context.Background(), "ConsumeSlotReclaim uid=", uid, " slot=", slot, ": ", err)
			return false, ""
		}
		return ok, targetSlot
	}
}

func ConsumeReclaimGrant(tag string, uid int, slot string) ReclaimGrant {
	slot = strings.TrimSpace(slot)
	value, ok := reclaimers.Load(tag)
	if uid <= 0 || slot == "" || !ok {
		return ReclaimGrant{}
	}
	r := value.(*reclaimer)
	key := strconv.Itoa(uid) + "|" + slot
	if !r.hold(key) {
		return ReclaimGrant{}
	}
	granted, targetSlot := r.consume(uid, slot)
	r.release(key, granted)
	if !granted {
		return ReclaimGrant{}
	}
	return ReclaimGrant{Granted: true, TargetSlot: strings.TrimSpace(targetSlot)}
}

// hold 占住这次询问：同一设备并发的连接只问一次面板，被拒后 reclaimRetryAfter 内直接按拒绝处理。
func (r *reclaimer) hold(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for k, until := range r.held {
		if !now.Before(until) {
			delete(r.held, k)
		}
	}
	if _, held := r.held[key]; held {
		return false
	}
	r.held[key] = now.Add(reclaimRetryAfter)
	return true
}

func (r *reclaimer) release(key string, granted bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if granted {
		delete(r.held, key)
	} else {
		r.held[key] = time.Now().Add(reclaimRetryAfter)
	}
}
