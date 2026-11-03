package hysteria2

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/apernet/hysteria/core/v2/server"

	"github.com/ECYCloud/ECYCloudNode/common/netguard"
	"github.com/ECYCloud/ECYCloudNode/common/rule"
)

// publicOutbound replaces hysteria's default outbound, which dials any address the
// client names, with one that keeps users off the node's loopback and private networks.
type publicOutbound struct {
	rules *rule.Manager
	tag   string
}

var errAuditBlocked = errors.New("blocked by audit rule")

var publicDialer = net.Dialer{Timeout: 10 * time.Second}

func (publicOutbound) TCP(reqAddr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(reqAddr)
	if err != nil {
		return nil, err
	}
	addrs, err := netguard.PublicAddrs(context.Background(), host)
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		var conn net.Conn
		if conn, err = publicDialer.Dial("tcp", net.JoinHostPort(addr.String(), port)); err == nil {
			return conn, nil
		}
	}
	return nil, err
}

func (publicOutbound) UDP(string) (server.UDPConn, error) {
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	return &publicUDPConn{conn}, nil
}

// CheckUDP 的结果按会话缓存，私网拦截因此放在 WriteTo 逐包做；这里补上全锥 UDP 后续目标的审计
// （首个目标已由带身份的 UDPRequest 审计）。内核不传用户身份，只能按没有豁免的规则拦截。
func (o publicOutbound) CheckUDP(reqAddr string) error {
	if o.rules != nil && o.rules.DetectUnexempted(o.tag, reqAddr) {
		return errAuditBlocked
	}
	return nil
}

type publicUDPConn struct {
	*net.UDPConn
}

func (c *publicUDPConn) ReadFrom(b []byte) (int, string, error) {
	n, addr, err := c.UDPConn.ReadFrom(b)
	if addr == nil {
		return n, "", err
	}
	return n, addr.String(), err
}

func (c *publicUDPConn) WriteTo(b []byte, addr string) (int, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, err
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return 0, err
	}
	addrs, err := netguard.PublicAddrs(context.Background(), host)
	if err != nil {
		return 0, err
	}
	return c.UDPConn.WriteToUDPAddrPort(b, netip.AddrPortFrom(addrs[0], uint16(portNumber)))
}
