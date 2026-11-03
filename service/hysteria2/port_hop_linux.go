//go:build linux
// +build linux

package hysteria2

import (
	"fmt"
	"os/exec"

	log "github.com/sirupsen/logrus"
)

// applyPortHopIptablesRules installs iptables NAT PREROUTING rules for the
// given port ranges so that traffic to the external ports is redirected to the
// underlying Hysteria2 server port. The generated commands are intentionally
// equivalent to the manual examples provided by the user, e.g.:
//
//   iptables -t nat -A PREROUTING -p udp --dport 30001:50000 -j REDIRECT --to-port 30000
func applyPortHopIptablesRules(rules []portHopRule, logger *log.Entry) {
	for _, r := range rules {
		// 已装规则只记在内存里：进程崩溃或被强杀后残留的同一条规则直接接管，重启时不再重复追加
		if _, err := portHopIptables("-C", r); err == nil {
			logger.Debugf("Hysteria2 port hop: iptables rule already present (%v)", r)
			continue
		}
		if out, err := portHopIptables("-A", r); err != nil {
			logger.Errorf("Hysteria2 port hop: failed to add iptables rule (%v): %v, output: %s", r, err, string(out))
		} else {
			logger.Debugf("Hysteria2 port hop: added iptables rule (%v)", r)
		}
	}
}

// deletePortHopIptablesRules removes previously installed iptables rules. Each
// rule must match exactly the arguments used when it was added.
func deletePortHopIptablesRules(rules []portHopRule, logger *log.Entry) {
	for _, r := range rules {
		if out, err := portHopIptables("-D", r); err != nil {
			// If the rule no longer exists we just log at debug level instead of
			// failing hard, to keep behavior close to manually running iptables -D.
			logger.Debugf("Hysteria2 port hop: failed to delete iptables rule (%v): %v, output: %s", r, err, string(out))
		} else {
			logger.Debugf("Hysteria2 port hop: deleted iptables rule (%v)", r)
		}
	}
}

// portHopIptables 以 action（-A / -C / -D）操作同一条规则：三者参数必须完全一致，iptables 才认作同一条。
func portHopIptables(action string, r portHopRule) ([]byte, error) {
	dport := fmt.Sprintf("%d", r.FromPortStart)
	if r.FromPortStart != r.FromPortEnd {
		dport = fmt.Sprintf("%d:%d", r.FromPortStart, r.FromPortEnd)
	}
	return exec.Command("iptables", "-t", "nat", action, "PREROUTING", "-p", "udp", "--dport", dport,
		"-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", r.ToPort)).CombinedOutput()
}
