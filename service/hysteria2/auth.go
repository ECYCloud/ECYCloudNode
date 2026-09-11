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

	user, ok := a.svc.users[auth]
	if !ok {
		a.svc.mu.Unlock()
		logger.WithFields(log.Fields{
			"remote": host,
			"auth":   auth,
		}).Warn("Hysteria2 auth failed: unknown UUID")
		return false, ""
	}

	// 官方客户端按设备标识占名额，换网络不重复占用；第三方仍按出口 IP
	slot := limiter.OnlineKey(user.ClientID, host)

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
