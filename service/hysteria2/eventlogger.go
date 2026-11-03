package hysteria2

import (
	"fmt"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

// maxUDPSessionsPerConn 是单条连接同时保有的 UDP 会话上限：内核不限会话数，每个会话各占一个出站
// UDP 套接字，一条连接就能耗尽本机的临时端口与文件描述符。上限放宽到正常客户端用不到的量。
const maxUDPSessionsPerConn = 1024

// udpSessionLimitLog 让超限日志每分钟最多一条：超限的连接在断开前还可能继续开会话。
var udpSessionLimitLog = rate.Sometimes{Interval: time.Minute}

// hyEventLogger implements server.EventLogger and prints useful
// diagnostics so that connection and handshake issues can be
// investigated from ECYCloudNode's log output.
type hyEventLogger struct {
	svc *Hysteria2Service
}

func (l *hyEventLogger) logger() *log.Entry {
	if l == nil || l.svc == nil || l.svc.logger == nil {
		return log.NewEntry(log.StandardLogger())
	}
	return l.svc.logger
}

// userFields resolves the given Hysteria2 connection ID (which is the
// auth string returned by the Authenticator) to a stable, non-sensitive
// user identity such as UID / email for logging purposes.
func (l *hyEventLogger) userFields(id string) log.Fields {
	fields := log.Fields{}
	if l == nil || l.svc == nil {
		return fields
	}

	cred, _ := splitAuthID(id)

	l.svc.mu.RLock()
	defer l.svc.mu.RUnlock()

	if user, ok := l.svc.users[cred]; ok {
		fields["uid"] = user.UID
	}
	return fields
}

func (l *hyEventLogger) auditRequest(id, reqAddr string) bool {
	if l == nil || l.svc == nil || l.svc.rules == nil {
		return false
	}

	cred, host := splitAuthID(id)

	l.svc.mu.RLock()
	user, ok := l.svc.users[cred]
	l.svc.mu.RUnlock()
	if !ok || reqAddr == "" {
		return false
	}

	userKey := fmt.Sprintf("%d", user.UID)
	if l.svc.rules.Detect(l.svc.tag, reqAddr, userKey, host) {
		// Mark this connection ID as blocked. The TrafficLogger will see this
		// flag and return false on the next traffic callback, which instructs
		// the Hysteria2 core to disconnect the client immediately.
		if l.svc.blockedIDs != nil {
			l.svc.mu.Lock()
			l.svc.blockedIDs[id] = true
			l.svc.mu.Unlock()
		}

		l.logger().WithFields(log.Fields{
			"remote":  host,
			"reqAddr": reqAddr,
			"uid":     user.UID,
		}).Warn("Hysteria2 audit rule hit, scheduling disconnect")
		return true
	}
	return false
}

func (l *hyEventLogger) Connect(addr net.Addr, id string, tx uint64) {
	fields := log.Fields{
		"remote": addr.String(),
	}
	for k, v := range l.userFields(id) {
		fields[k] = v
	}
	l.logger().WithFields(fields).Info("Hysteria2 client connected")
}

func (l *hyEventLogger) Disconnect(addr net.Addr, id string, err error) {
	remote := ""
	if addr != nil {
		remote = addr.String()
	}

	fields := log.Fields{
		"remote": remote,
	}
	for k, v := range l.userFields(id) {
		fields[k] = v
	}

	// 归还该会话占用的名额。地址取自连接标识，与登记时同一口径
	cred, host := splitAuthID(id)
	if l != nil && l.svc != nil && cred != "" && host != "" {
		l.svc.releaseOnline(id)
	}

	if err != nil {
		fields["err"] = err
		l.logger().WithFields(fields).Warn("Hysteria2 client disconnected with error")
	} else {
		l.logger().WithFields(fields).Info("Hysteria2 client disconnected")
	}
}

func (l *hyEventLogger) TCPRequest(addr net.Addr, id, reqAddr string) {
	remote := ""
	if addr != nil {
		remote = addr.String()
	}
	cred, _ := splitAuthID(id)

	var (
		user    userRecord
		ok      bool
		nodeTag string
	)

	if l != nil && l.svc != nil {
		nodeTag = l.svc.tag

		l.svc.mu.RLock()
		user, ok = l.svc.users[cred]
		l.svc.mu.RUnlock()

		// 存活会话的周期性复查：续期仍持有的名额，已被超限挤出的则断连；
		// 被挤出后禁止靠流量抢回名额
		l.svc.guardOnline(id)
	}

	if ok {
		l.logger().Infof("from %s accepted tcp:%s [%s] uid: %d",
			remote, reqAddr, nodeTag, user.UID)
	} else {
		l.logger().Infof("from %s accepted tcp:%s [%s]",
			remote, reqAddr, nodeTag)
	}

	l.auditRequest(id, reqAddr)
}

func (l *hyEventLogger) TCPError(addr net.Addr, id, reqAddr string, err error) {
	fields := log.Fields{
		"remote":  addr.String(),
		"reqAddr": reqAddr,
	}
	for k, v := range l.userFields(id) {
		fields[k] = v
	}
	if err != nil {
		fields["err"] = err
		l.logger().WithFields(fields).Warn("Hysteria2 TCP error")
	} else {
		l.logger().WithFields(fields).Debug("Hysteria2 TCP error")
	}
}

func (l *hyEventLogger) UDPRequest(addr net.Addr, id string, sessionID uint32, reqAddr string) {
	remote := ""
	if addr != nil {
		remote = addr.String()
	}
	cred, _ := splitAuthID(id)

	var (
		user    userRecord
		ok      bool
		nodeTag string
	)

	if l != nil && l.svc != nil {
		nodeTag = l.svc.tag

		l.svc.mu.RLock()
		user, ok = l.svc.users[cred]
		l.svc.mu.RUnlock()

		// 存活会话的周期性复查：续期仍持有的名额，已被超限挤出的则断连；
		// 被挤出后禁止靠流量抢回名额
		l.svc.guardOnline(id)
	}

	if ok {
		l.logger().Infof("from %s accepted udp:%s [%s] uid: %d",
			remote, reqAddr, nodeTag, user.UID)
	} else {
		l.logger().Infof("from %s accepted udp:%s [%s]",
			remote, reqAddr, nodeTag)
	}

	l.auditRequest(id, reqAddr)

	if l != nil && l.svc != nil && l.svc.trackUDPSession(id, sessionID) {
		udpSessionLimitLog.Do(func() {
			l.logger().WithFields(log.Fields{
				"remote": remote,
				"uid":    user.UID,
				"limit":  maxUDPSessionsPerConn,
			}).Warn("Hysteria2 connection exceeded the UDP session limit, disconnecting")
		})
	}
}

// trackUDPSession 登记连接新开的 UDP 会话；超出上限时标记断连，由 LogTraffic 在下一个流量事件
// 通知内核断开整条连接（与审计命中共用同一机制）。
func (h *Hysteria2Service) trackUDPSession(id string, sessionID uint32) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.udpSessions == nil {
		h.udpSessions = make(map[string]map[uint32]struct{})
	}
	sessions := h.udpSessions[id]
	if sessions == nil {
		sessions = make(map[uint32]struct{})
		h.udpSessions[id] = sessions
	}
	sessions[sessionID] = struct{}{}
	if len(sessions) <= maxUDPSessionsPerConn {
		return false
	}
	if h.blockedIDs != nil {
		h.blockedIDs[id] = true
	}
	return true
}

// untrackUDPSession 归还已关闭会话的额度。连接断开时内核会逐个关闭其全部会话，账目随之清空。
func (h *Hysteria2Service) untrackUDPSession(id string, sessionID uint32) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if sessions := h.udpSessions[id]; sessions != nil {
		delete(sessions, sessionID)
		if len(sessions) == 0 {
			delete(h.udpSessions, id)
		}
	}
}

func (l *hyEventLogger) UDPError(addr net.Addr, id string, sessionID uint32, err error) {
	if l != nil && l.svc != nil {
		l.svc.untrackUDPSession(id, sessionID)
	}
	fields := log.Fields{
		"remote":    addr.String(),
		"sessionID": sessionID,
	}
	for k, v := range l.userFields(id) {
		fields[k] = v
	}
	if err != nil {
		fields["err"] = err
		l.logger().WithFields(fields).Warn("Hysteria2 UDP error")
	} else {
		l.logger().WithFields(fields).Debug("Hysteria2 UDP error")
	}
}
