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
	"golang.org/x/time/rate"
)

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
	svc     *TuicService
	user    string
	host    string
	blocked bool
	limiter *rate.Limiter
}

func (c *connCounter) Read(p []byte) (int, error) {
	if c.blocked {
		return 0, io.EOF
	}
	n, err := c.Conn.Read(p)
	if n > 0 && c.svc != nil {
		c.svc.addTraffic(c.user, int64(n), 0)
		// 仅上行（客户端发来的数据）能证明客户端存活，据此续期在线时间；
		// 下行不续期，避免客户端离线后残留连接被远端数据无限"续命"
		if !c.svc.ensureOnline(c.user, c.host) {
			_ = c.Conn.Close()
		}
		if c.limiter != nil {
			_ = c.limiter.WaitN(context.Background(), n)
		}
	}
	return n, err
}

func (c *connCounter) Write(p []byte) (int, error) {
	if c.blocked {
		return 0, io.EOF
	}
	n, err := c.Conn.Write(p)
	if n > 0 && c.svc != nil {
		c.svc.addTraffic(c.user, 0, int64(n))
		// 名额已被挤出且账号名额已满：超限设备的既有下行连接必须断开，
		// 否则大文件下载之类的长连接能一直跑完
		if !c.svc.verifyOnline(c.user, c.host) {
			_ = c.Conn.Close()
		}
		if c.limiter != nil {
			_ = c.limiter.WaitN(context.Background(), n)
		}
	}
	return n, err
}

type packetConnCounter struct {
	N.PacketConn
	svc     *TuicService
	user    string
	host    string
	blocked bool
	limiter *rate.Limiter
}

// ReadPacket implements N.PacketReader to count upload traffic (user -> proxy).
func (c *packetConnCounter) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	if c.blocked {
		return M.Socksaddr{}, io.EOF
	}
	destination, err = c.PacketConn.ReadPacket(buffer)
	n := buffer.Len()
	if n > 0 && c.svc != nil {
		c.svc.addTraffic(c.user, int64(n), 0)
		if !c.svc.ensureOnline(c.user, c.host) {
			_ = c.PacketConn.Close()
		}
		if c.limiter != nil {
			_ = c.limiter.WaitN(context.Background(), n)
		}
	}
	return destination, err
}

// WritePacket implements N.PacketWriter to count download traffic (proxy -> user).
func (c *packetConnCounter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if c.blocked {
		return io.EOF
	}
	n := buffer.Len()
	err := c.PacketConn.WritePacket(buffer, destination)
	if err == nil && n > 0 && c.svc != nil {
		c.svc.addTraffic(c.user, 0, int64(n))
		if !c.svc.verifyOnline(c.user, c.host) {
			_ = c.PacketConn.Close()
		}
		if c.limiter != nil {
			_ = c.limiter.WaitN(context.Background(), n)
		}
	}
	return err
}

type tuicTracker struct {
	svc *TuicService
}

var _ adapter.ConnectionTracker = (*tuicTracker)(nil)

func (t *tuicTracker) RoutedConnection(_ context.Context, conn net.Conn, m adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	if t.svc == nil {
		return conn
	}
	if m.User == "" {
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
	if ok && dest != "" && t.svc.rules != nil {
		userKey := fmt.Sprintf("%d", userRec.UID)
		if t.svc.rules.Detect(t.svc.tag, dest, userKey, host) {
			t.svc.logger.WithFields(fields).Warn("TUIC audit rule hit, closing connection")
			blocked = true
		}
	}

	// Device limit check (only if not already blocked by audit).
	if !blocked && !t.svc.allowConnection(m.User, host) {
		// allowConnection already logs a warning when device limit is exceeded.
		blocked = true
	}

	// Attach per-user rate limiter if configured.
	var limiter *rate.Limiter
	t.svc.mu.RLock()
	if t.svc.rateLimiters != nil {
		limiter = t.svc.rateLimiters[m.User]
	}
	t.svc.mu.RUnlock()

	if blocked {
		_ = conn.Close()
		return &connCounter{Conn: conn, svc: t.svc, user: m.User, host: host, blocked: true, limiter: limiter}
	}

	return &connCounter{Conn: conn, svc: t.svc, user: m.User, host: host, limiter: limiter}
}

func (t *tuicTracker) RoutedPacketConnection(_ context.Context, conn N.PacketConn, m adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
	if t.svc == nil {
		return conn
	}
	if m.User == "" {
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
	if ok && dest != "" && t.svc.rules != nil {
		userKey := fmt.Sprintf("%d", userRec.UID)
		srcIP := host
		if t.svc.rules.Detect(t.svc.tag, dest, userKey, srcIP) {
			t.svc.logger.WithFields(fields).Warn("TUIC audit rule hit on UDP, closing connection")
			blocked = true
		}
	}

	// Device limit check (only if not already blocked by audit).
	if !blocked && !t.svc.allowConnection(m.User, host) {
		// allowConnection already logs a warning when device limit is exceeded.
		blocked = true
	}

	// Attach per-user rate limiter if configured.
	var limiter *rate.Limiter
	t.svc.mu.RLock()
	if t.svc.rateLimiters != nil {
		limiter = t.svc.rateLimiters[m.User]
	}
	t.svc.mu.RUnlock()

	if blocked {
		_ = conn.Close()
		return &packetConnCounter{PacketConn: conn, svc: t.svc, user: m.User, host: host, blocked: true, limiter: limiter}
	}

	return &packetConnCounter{PacketConn: conn, svc: t.svc, user: m.User, host: host, limiter: limiter}
}

// RoutedFlow 仅在 TUN inbound 的 pre-match 流转发路径上被调用，TUIC 节点不注册
// TUN inbound，因此这里无需统计；返回 nil 由 sing-box 的 router 自行跳过。
func (t *tuicTracker) RoutedFlow(_ context.Context, _ adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) tun.FlowTracker {
	return nil
}
