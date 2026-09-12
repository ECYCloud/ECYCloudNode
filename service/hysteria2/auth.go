package hysteria2

import (
	"net"
	"time"

	"github.com/ECYCloud/ECYCloudNode/common/limiter"
	log "github.com/sirupsen/logrus"
)

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

	ipSet, ok := a.svc.onlineIPs[auth]
	if !ok {
		ipSet = make(map[string]struct{})
		a.svc.onlineIPs[auth] = ipSet
	}

	// Initialize ipLastActive map for this user if not exists
	activeMap, ok := a.svc.ipLastActive[auth]
	if !ok {
		activeMap = make(map[string]time.Time)
		a.svc.ipLastActive[auth] = activeMap
	}

	allowed, grant := limiter.AdmitDeviceIP(ipSet, activeMap, slot, user.UID, user.DeviceLimit)
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
		delete(a.svc.onlineIPs[auth], slot)
		if am, ok := a.svc.ipLastActive[auth]; ok {
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

	return true, auth
}

// slot 解析该凭据在 host 上占用的名额标识，与 Authenticate 同一口径：
// 官方客户端按设备标识占名额，第三方按出口 IP。调用方须自行持锁。
func (h *Hysteria2Service) slot(id, host string) (string, userRecord, bool) {
	user, ok := h.users[id]
	if !ok {
		return "", user, false
	}
	return limiter.OnlineKey(user.ClientID, host), user, true
}

// ensureOnline 复查并续期该凭据持有的名额；已被挤出或已过期返回 false。
func (h *Hysteria2Service) ensureOnline(id, host string) bool {
	h.mu.Lock()
	slot, user, ok := h.slot(id, host)
	if !ok {
		h.mu.Unlock()
		return false
	}
	online, due := limiter.EnsureDeviceIP(h.onlineIPs[id], h.ipLastActive[id], slot)
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

// guardOnline 是存活会话的周期性复查入口：名额已被挤出时标记断开，
// 由 LogTraffic 在下一个流量事件通知内核断连（与审计命中共用同一机制）。
func (h *Hysteria2Service) guardOnline(id, host string) {
	if id == "" || host == "" || h.ensureOnline(id, host) {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.blockedIDs != nil {
		h.blockedIDs[id] = true
	}
}

// releaseOnline 归还该凭据在 host 上占用的名额。一个 Hysteria2 会话就是一台设备，
// 会话结束即可释放；异常离线不会走到这里，由活跃时间过期兜底。
func (h *Hysteria2Service) releaseOnline(id, host string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	slot, _, ok := h.slot(id, host)
	if !ok {
		return
	}
	if ipSet, exists := h.onlineIPs[id]; exists {
		delete(ipSet, slot)
		if len(ipSet) == 0 {
			delete(h.onlineIPs, id)
		}
	}
	if activeMap, exists := h.ipLastActive[id]; exists {
		delete(activeMap, slot)
		if len(activeMap) == 0 {
			delete(h.ipLastActive, id)
		}
	}
}
