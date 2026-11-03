// Package netguard keeps relayed user traffic away from the node's own loopback,
// private and other special-purpose networks.
package netguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
)

// 必须与 xray-core common/geodata 的 privateIPMatcher 逐条一致：同一节点的 xray 入站经 freedom 默认按那份清单拦截。
var blockedCIDRs = []string{
	"0.0.0.0/8",
	"0.0.0.0/32",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/29",
	"192.0.0.8/32",
	"192.0.0.9/32",
	"192.0.0.10/32",
	"192.0.0.170/32",
	"192.0.0.171/32",
	"192.0.2.0/24",
	"192.52.193.0/24",
	"192.88.99.2/32",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"240.0.0.0/4",
	"255.255.255.255/32",
	"224.0.0.0/4",
	"::1/128",
	"::/128",
	"64:ff9b::/96",
	"64:ff9b:1::/48",
	"100::/64",
	"100:0:0:1::/64",
	"2001::/32",
	"2001:1::1/128",
	"2001:1::2/128",
	"2001:1::3/128",
	"2001:2::/48",
	"2001:3::/32",
	"2001:20::/28",
	"2001:30::/28",
	"2001:db8::/32",
	"2002::/16",
	"3fff::/20",
	"5f00::/16",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
}

var blockedPrefixes = sync.OnceValue(func() []netip.Prefix {
	prefixes := make([]netip.Prefix, len(blockedCIDRs))
	for i, cidr := range blockedCIDRs {
		prefixes[i] = netip.MustParsePrefix(cidr)
	}
	return prefixes
})

var ErrBlocked = errors.New("destination is a private or reserved address")

const resolveTimeout = 5 * time.Second

var loopbackReachable atomic.Bool

// AllowLoopbackForTesting lets end-to-end tests reach echo servers on loopback and
// returns the previous setting. Production code must never call it.
func AllowLoopbackForTesting(allow bool) bool {
	return loopbackReachable.Swap(allow)
}

func Blocked(addr netip.Addr) bool {
	addr = addr.Unmap()
	if addr.IsLoopback() && loopbackReachable.Load() {
		return false
	}
	for _, prefix := range blockedPrefixes() {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// PublicAddrs resolves host once; callers must dial the returned addresses instead of
// resolving again, otherwise a rebinding DNS answer could still reach a blocked network.
func PublicAddrs(ctx context.Context, host string) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		if Blocked(addr) {
			return nil, ErrBlocked
		}
		return []netip.Addr{addr.Unmap()}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	for i, addr := range addrs {
		if Blocked(addr) {
			return nil, ErrBlocked
		}
		addrs[i] = addr.Unmap()
	}
	if len(addrs) == 0 {
		return nil, ErrBlocked
	}
	return addrs, nil
}

// PublicDestination rewrites a domain destination to a checked address so the
// outbound sends the packet without resolving the name a second time.
func PublicDestination(destination M.Socksaddr) (M.Socksaddr, bool) {
	switch {
	case destination.IsIP():
		return destination, !Blocked(destination.Addr)
	case destination.IsFqdn():
		addrs, err := PublicAddrs(context.Background(), destination.Fqdn)
		if err != nil {
			return destination, false
		}
		return M.SocksaddrFrom(addrs[0], destination.Port), true
	default:
		// 不带目标的包沿用会话目标，该目标已由 SingBoxRules 在路由时检查
		return destination, true
	}
}

// SingBoxRules resolves domain destinations in the router so the direct outbound dials
// the same addresses that were checked, then rejects blocked networks before dialing.
func SingBoxRules() []option.Rule {
	cidrs := make([]string, 0, len(blockedCIDRs))
	for _, cidr := range blockedCIDRs {
		if prefix := netip.MustParsePrefix(cidr); !loopbackReachable.Load() || !prefix.Addr().IsLoopback() {
			cidrs = append(cidrs, cidr)
		}
	}
	return []option.Rule{
		{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RuleAction: option.RuleAction{Action: C.RuleActionTypeResolve},
			},
		},
		{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{IPCIDR: badoption.Listable[string](cidrs)},
				// 直接构造选项不会经过 JSON 解码补默认值，Method 留空会让 sing-box 在路由时 panic
				RuleAction: option.RuleAction{
					Action:        C.RuleActionTypeReject,
					RejectOptions: option.RejectActionOptions{Method: C.RuleActionRejectMethodDefault},
				},
			},
		},
	}
}
