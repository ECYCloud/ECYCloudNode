package hysteria2

import (
	"net"
	"strings"
	"time"

	"github.com/ECYCloud/ECYCloudNode/common/limiter"
	log "github.com/sirupsen/logrus"
)

// authID 是 Authenticate 交还给内核的连接标识。内核只把它原样回传给各个回调，
// 自身不解析内容，因此把来源地址编进去；否则不带地址的回调（LogTraffic）无法
// 区分同一凭据下的多条连接，第三方按出口 IP 计的名额就定位不到。
func authID(cred, host string) string {
	return cred + "|" + host
}

// splitAuthID 从连接标识拆回凭据与来源地址。按最后一个分隔符切分：IPv6 地址不含
// "|"，而凭据理论上可能含，从右侧拆才不会把凭据截断。旧格式（无分隔符）退化为
// 只有凭据，此时按无地址处理。
func splitAuthID(id string) (cred, host string) {
	if i := strings.LastIndex(id, "|"); i >= 0 {
		return id[:i], id[i+1:]
	}
	return id, ""
}

// hyAuthenticator implements server.Authenticator and performs user lookup
// and local device limit enforcement based on SSPanel's UUID.
type hyAuthenticator struct {
	svc *Hysteria2Service
}

func (a *hyAuthenticator) Authenticate(addr net.Addr, auth string, tx uint64) (bool, string) {
	logger := log.NewEntry(log.StandardLogger())
	if a.svc != nil && a.svc.logger != nil {
		logger = a.svc.logger
	}

	host := addr.String()
	if h, _, err := net.SplitHostPort(addr.String()); err == nil {
		host = h
	}

	if auth == "" {
		logger.WithField("remote", host).Warn("Hysteria2 auth failed: empty auth string")
		return false, ""
	}

	a.svc.mu.Lock()

	// 官方客户端按设备标识占名额，换网络不重复占用；第三方仍按出口 IP
	slot, user, ok := a.svc.slot(auth, host)
	if !ok {
		a.svc.mu.Unlock()
		logger.WithFields(log.Fields{
			"remote": host,
			"auth":   auth,
		}).Warn("Hysteria2 auth failed: unknown UUID")
		return false, ""
	}

	slotSet, ok := a.svc.onlineSlots[auth]
	if !ok {
		slotSet = make(map[string]struct{})
		a.svc.onlineSlots[auth] = slotSet
	}

	// Initialize slotLastActive map for this user if not exists
	activeMap, ok := a.svc.slotLastActive[auth]
	if !ok {
		activeMap = make(map[string]time.Time)
		a.svc.slotLastActive[auth] = activeMap
	}

	allowed, grant := limiter.AdmitDeviceSlot(slotSet, activeMap, slot, user.UID, user.DeviceLimit)
	a.svc.mu.Unlock()
	if !allowed {
		logger.WithFields(log.Fields{
			"uid":         user.UID,
			"deviceLimit": user.DeviceLimit,
			"remote":      host,
		}).Warn("Hysteria2 user exceeded device limit")
		return false, ""
	}

	// 全局（跨节点）限制：涉及 Redis 访问，必须在锁外执行
	if !a.svc.globalChecker.Allow(user.UID, slot, user.DeviceLimit, grant) {
		a.svc.mu.Lock()
		delete(a.svc.onlineSlots[auth], slot)
		if am, ok := a.svc.slotLastActive[auth]; ok {
			delete(am, slot)
		}
		a.svc.mu.Unlock()
		logger.WithFields(log.Fields{
			"uid":         user.UID,
			"deviceLimit": user.DeviceLimit,
			"remote":      host,
		}).Warn("Hysteria2 user exceeded global device limit")
		return false, ""
	}

	return true, authID(auth, host)
}

// slot 解析该凭据在 host 上占用的名额标识，与 Authenticate 同一口径：
// 官方客户端按设备标识占名额，第三方按出口 IP。
// cred 是认证凭据，不是回调传来的连接标识，后者须先经 splitAuthID 拆开。
// 调用方须自行持锁。
func (h *Hysteria2Service) slot(cred, host string) (string, userRecord, bool) {
	user, ok := h.users[cred]
	if !ok {
		return "", user, false
	}
	return limiter.OnlineKey(user.ClientID, host), user, true
}

// ensureOnline 复查并续期该凭据持有的名额；已被挤出或已过期返回 false。
func (h *Hysteria2Service) ensureOnline(cred, host string) bool {
	h.mu.Lock()
	slot, user, ok := h.slot(cred, host)
	if !ok {
		h.mu.Unlock()
		return false
	}
	online, due := limiter.EnsureDeviceSlot(h.onlineSlots[cred], h.slotLastActive[cred], slot)
	h.mu.Unlock()

	// 不限设备数的账号没有名额可守，复查只为续期，不据此断连
	if user.DeviceLimit <= 0 {
		return true
	}
	if !online {
		return false
	}
	if !due {
		return true
	}
	// 全局（跨节点）限制：涉及 Redis 访问，必须在锁外执行
	return h.globalChecker.Refresh(user.UID, slot, user.DeviceLimit)
}

// verifyOnline 下行方向（远端→客户端）的复查：只核查不续期。下行流量不能证明客户端
// 仍然存活——客户端异常离线后远端仍可能向残留连接推送数据，据此续期会让离线名额被
// 无限续命、永不释放；但被挤出的设备必须断开，否则大文件下载之类的长连接能一直跑完。
func (h *Hysteria2Service) verifyOnline(cred, host string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	slot, user, ok := h.slot(cred, host)
	if !ok {
		return false
	}
	return limiter.VerifyDeviceSlot(h.slotLastActive[cred], slot, user.DeviceLimit)
}

// guardOnline 是存活会话的周期性复查入口：名额已被挤出时标记断开，
// 由 LogTraffic 在下一个流量事件通知内核断连（与审计命中共用同一机制）。
func (h *Hysteria2Service) guardOnline(cred, host string) {
	if cred == "" || host == "" || h.ensureOnline(cred, host) {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.blockedIDs != nil {
		// 断连标记按连接记：同一凭据下只断被挤掉的那条，不牵连其它在线连接
		h.blockedIDs[authID(cred, host)] = true
	}
}

// releaseOnline 清理连接结束时该归还的状态：名额与断连标记。一个 Hysteria2 会话就是
// 一台设备，会话结束即可释放；异常离线不会走到这里，由活跃时间过期兜底。
func (h *Hysteria2Service) releaseOnline(cred, host string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// 连接没了，断连标记再没有流量事件来消费，就地清掉；否则标记表会随来源地址无限增长
	delete(h.blockedIDs, authID(cred, host))

	slot, _, ok := h.slot(cred, host)
	if !ok {
		return
	}
	if slotSet, exists := h.onlineSlots[cred]; exists {
		delete(slotSet, slot)
		if len(slotSet) == 0 {
			delete(h.onlineSlots, cred)
		}
	}
	if activeMap, exists := h.slotLastActive[cred]; exists {
		delete(activeMap, slot)
		if len(activeMap) == 0 {
			delete(h.slotLastActive, cred)
		}
	}
}
