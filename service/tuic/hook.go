package tuic

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	log "github.com/sirupsen/logrus"

	"github.com/ECYCloud/ECYCloudNode/common/netguard"
)

const maxAuditedTargets = 256

// auditHit 同时审计目标地址与嗅探出的域名：嗅探不改写目标，只查域名会让伪造 SNI 的 IP 直连绕过 IP 规则。
func (s *TuicService) auditHit(m adapter.InboundContext, uid int, host string) bool {
	if s.rules == nil {
		return false
	}
	targets := []string{m.Domain}
	if m.Destination.IsValid() {
		targets = append(targets, m.Destination.String())
	}
	for _, target := range targets {
		if target != "" && s.rules.Detect(s.tag, target, fmt.Sprintf("%d", uid), host) {
			return true
		}
	}
	return false
}

// remoteHost 取出连接来源的主机部分，名额的登记与复查共用它。
func remoteHost(remote string) string {
	host := remote
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "" {
		host = "unknown"
	}
	return host
}

type connCounter struct {
	net.Conn
	svc         *TuicService
	user        string
	identity    string
	uid         int
	host        string
	blocked     bool
	kickVersion uint64
}

func (c *connCounter) Read(p []byte) (int, error) {
	if c.blocked {
		return 0, io.EOF
	}
	n, err := c.Conn.Read(p)
	if n > 0 && c.svc != nil {
		if recordErr := c.svc.addTraffic(c.uid, int64(n), 0, c.identity); recordErr != nil {
			_ = c.Close()
			return 0, recordErr
		}
		// 仅上行（客户端发来的数据）能证明客户端存活，据此续期在线时间；
		// 下行不续期，避免客户端离线后残留连接被远端数据无限"续命"
		if !c.svc.ensureOnline(c.user, c.host, c.kickVersion) {
			_ = c.Conn.Close()
			return 0, io.EOF
		}
		if waitErr := c.svc.waitTraffic(c.user, n); waitErr != nil {
			_ = c.Close()
			return 0, waitErr
		}
		if !c.svc.ensureOnline(c.user, c.host, c.kickVersion) {
			_ = c.Close()
			return 0, io.EOF
		}
	}
	return n, err
}

func (c *connCounter) Write(p []byte) (int, error) {
	if c.blocked || (c.svc != nil && !c.svc.verifyOnline(c.user, c.host, c.kickVersion)) {
		return 0, io.EOF
	}
	if len(p) > 0 && c.svc != nil {
		if recordErr := c.svc.addTraffic(c.uid, 0, int64(len(p)), c.identity); recordErr != nil {
			_ = c.Close()
			return 0, recordErr
		}
		if waitErr := c.svc.waitTraffic(c.user, len(p)); waitErr != nil {
			_ = c.Close()
			return 0, waitErr
		}
		if !c.svc.verifyOnline(c.user, c.host, c.kickVersion) {
			_ = c.Close()
			return 0, io.EOF
		}
	}
	return c.Conn.Write(p)
}

type packetConnCounter struct {
	N.PacketConn
	svc         *TuicService
	user        string
	identity    string
	uid         int
	host        string
	blocked     bool
	kickVersion uint64
	verdicts    map[string]bool
}

// ReadPacket implements N.PacketReader to count upload traffic (user -> proxy).
func (c *packetConnCounter) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	if c.blocked {
		return M.Socksaddr{}, io.EOF
	}
	// 全锥 UDP 的后续包可发往任意目标，路由规则只检查过首包
	start := buffer.Start()
	for {
		destination, err = c.PacketConn.ReadPacket(buffer)
		var allowed bool
		if destination, allowed = netguard.PublicDestination(destination); err != nil || (allowed && c.audited(destination)) {
			break
		}
		buffer.Resize(start, 0)
	}
	n := buffer.Len()
	if n > 0 && c.svc != nil {
		if recordErr := c.svc.addTraffic(c.uid, int64(n), 0, c.identity); recordErr != nil {
			_ = c.Close()
			return M.Socksaddr{}, recordErr
		}
		if !c.svc.ensureOnline(c.user, c.host, c.kickVersion) {
			_ = c.PacketConn.Close()
			return M.Socksaddr{}, io.EOF
		}
		if waitErr := c.svc.waitTraffic(c.user, n); waitErr != nil {
			_ = c.Close()
			return M.Socksaddr{}, waitErr
		}
		if !c.svc.ensureOnline(c.user, c.host, c.kickVersion) {
			_ = c.Close()
			return M.Socksaddr{}, io.EOF
		}
	}
	return destination, err
}

// audited 逐个目标审计全锥 UDP：路由时的审计只看到同一 UDP 关联的首个目标。
func (c *packetConnCounter) audited(destination M.Socksaddr) bool {
	if c.svc == nil || c.svc.rules == nil {
		return true
	}
	target := destination.String()
	if allowed, ok := c.verdicts[target]; ok {
		return allowed
	}
	allowed := !c.svc.rules.Detect(c.svc.tag, target, fmt.Sprintf("%d", c.uid), c.host)
	if !allowed {
		c.svc.logger.WithFields(log.Fields{"uid": c.uid, "remote": c.host, "dest": target}).Warn("TUIC audit rule hit on UDP packet, dropping")
	}
	if c.verdicts == nil || len(c.verdicts) >= maxAuditedTargets {
		c.verdicts = make(map[string]bool)
	}
	c.verdicts[target] = allowed
	return allowed
}

// WritePacket implements N.PacketWriter to count download traffic (proxy -> user).
func (c *packetConnCounter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if c.blocked || (c.svc != nil && !c.svc.verifyOnline(c.user, c.host, c.kickVersion)) {
		buffer.Release()
		return io.EOF
	}
	n := buffer.Len()
	if n > 0 && c.svc != nil {
		if recordErr := c.svc.addTraffic(c.uid, 0, int64(n), c.identity); recordErr != nil {
			buffer.Release()
			_ = c.Close()
			return recordErr
		}
		if waitErr := c.svc.waitTraffic(c.user, n); waitErr != nil {
			buffer.Release()
			_ = c.Close()
			return waitErr
		}
		if !c.svc.verifyOnline(c.user, c.host, c.kickVersion) {
			buffer.Release()
			_ = c.Close()
			return io.EOF
		}
	}
	return c.PacketConn.WritePacket(buffer, destination)
}

type tuicTracker struct {
	svc *TuicService
}

var _ adapter.ConnectionTracker = (*tuicTracker)(nil)

func (t *tuicTracker) RoutedConnection(_ context.Context, conn net.Conn, m adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	if t.svc == nil {
		return conn
	}

	remote := ""
	if m.Source.Addr.IsValid() {
		remote = m.Source.Addr.String()
	}
	host := remoteHost(remote)

	var (
		userRec userRecord
		ok      bool
	)
	t.svc.mu.RLock()
	userRec, ok = t.svc.users[m.User]
	t.svc.mu.RUnlock()

	dest := m.Domain
	if dest == "" {
		dest = m.Destination.String()
	}

	fields := log.Fields{
		"remote": remote,
	}
	if dest != "" {
		fields["dest"] = dest
	}
	if ok {
		fields["uid"] = userRec.UID
	}

	// Access log: only expose UID, not email.
	nodeTag := t.svc.tag
	if ok {
		t.svc.logger.Infof("from %s accepted tcp:%s [%s] uid: %d",
			remote, dest, nodeTag, userRec.UID)
	} else {
		t.svc.logger.Infof("from %s accepted tcp:%s [%s]",
			remote, dest, nodeTag)
	}

	blocked := false

	// Audit check: if a rule hits, mark this connection as blocked and close it.
	if ok && t.svc.auditHit(m, userRec.UID, host) {
		t.svc.logger.WithFields(fields).Warn("TUIC audit rule hit, closing connection")
		blocked = true
	}

	// Device limit check (only if not already blocked by audit).
	if !blocked && !t.svc.allowConnection(m.User, host) {
		// allowConnection already logs a warning when device limit is exceeded.
		blocked = true
	}

	if blocked {
		_ = conn.Close()
		return &connCounter{Conn: conn, svc: t.svc, user: m.User, uid: userRec.UID, identity: userRec.TrafficIdentity, host: host, kickVersion: userRec.KickVersion, blocked: true}
	}

	return &connCounter{Conn: conn, svc: t.svc, user: m.User, uid: userRec.UID, identity: userRec.TrafficIdentity, host: host, kickVersion: userRec.KickVersion}
}

func (t *tuicTracker) RoutedPacketConnection(_ context.Context, conn N.PacketConn, m adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
	if t.svc == nil {
		return conn
	}

	remote := ""
	if m.Source.Addr.IsValid() {
		remote = m.Source.Addr.String()
	}
	host := remoteHost(remote)

	var (
		userRec userRecord
		ok      bool
	)
	t.svc.mu.RLock()
	userRec, ok = t.svc.users[m.User]
	t.svc.mu.RUnlock()

	dest := m.Domain
	if dest == "" {
		dest = m.Destination.String()
	}

	fields := log.Fields{
		"remote": remote,
	}
	if dest != "" {
		fields["dest"] = dest
	}
	if ok {
		fields["uid"] = userRec.UID
	}

	nodeTag := t.svc.tag
	if ok {
		t.svc.logger.Infof("from %s accepted udp:%s [%s] uid: %d",
			remote, dest, nodeTag, userRec.UID)
	} else {
		t.svc.logger.Infof("from %s accepted udp:%s [%s]",
			remote, dest, nodeTag)
	}

	blocked := false

	// Audit check for UDP: if a rule hits, block this logical session.
	if ok && t.svc.auditHit(m, userRec.UID, host) {
		t.svc.logger.WithFields(fields).Warn("TUIC audit rule hit on UDP, closing connection")
		blocked = true
	}

	// Device limit check (only if not already blocked by audit).
	if !blocked && !t.svc.allowConnection(m.User, host) {
		// allowConnection already logs a warning when device limit is exceeded.
		blocked = true
	}

	if blocked {
		_ = conn.Close()
		return &packetConnCounter{PacketConn: conn, svc: t.svc, user: m.User, uid: userRec.UID, identity: userRec.TrafficIdentity, host: host, kickVersion: userRec.KickVersion, blocked: true}
	}

	return &packetConnCounter{PacketConn: conn, svc: t.svc, user: m.User, uid: userRec.UID, identity: userRec.TrafficIdentity, host: host, kickVersion: userRec.KickVersion}
}

// RoutedFlow 仅在 TUN inbound 的 pre-match 流转发路径上被调用，TUIC 节点不注册
// TUN inbound，因此这里无需统计；返回 nil 由 sing-box 的 router 自行跳过。
func (t *tuicTracker) RoutedFlow(_ context.Context, _ adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) tun.FlowTracker {
	return nil
}
