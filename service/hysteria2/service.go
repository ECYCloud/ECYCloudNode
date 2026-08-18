package hysteria2

import (
	"errors"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/apernet/hysteria/core/v2/server"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/task"

	"github.com/ECYCloud/ECYCloudNode/api"
	"github.com/ECYCloud/ECYCloudNode/common/limiter"
	"github.com/ECYCloud/ECYCloudNode/common/rule"
	"github.com/ECYCloud/ECYCloudNode/service"
	"github.com/ECYCloud/ECYCloudNode/service/controller"
)

var _ service.Service = (*Hysteria2Service)(nil)

// rebuildRetryBackoffMax 是待重建重试的退避上限。
const rebuildRetryBackoffMax = 30 * time.Minute

// New creates a new Hysteria2 service bound to a SSPanel node.
func New(apiClient api.API, cfg *controller.Config) *Hysteria2Service {
	clientInfo := apiClient.Describe()
	logger := log.NewEntry(log.StandardLogger()).WithFields(log.Fields{
		"Host": clientInfo.APIHost,
		"ID":   clientInfo.NodeID,
	})
	var globalChecker *limiter.GlobalDeviceChecker
	if cfg != nil {
		globalChecker = limiter.NewGlobalDeviceChecker(cfg.GlobalDeviceLimitConfig)
	}
	return &Hysteria2Service{
		apiClient:     apiClient,
		config:        cfg,
		logger:        logger,
		rules:         rule.New(),
		globalChecker: globalChecker,
		users:         make(map[string]userRecord),
		traffic:       make(map[string]*userTraffic),
		overLimit:     make(map[string]bool),
		onlineIPs:     make(map[string]map[string]struct{}),
		ipLastActive:  make(map[string]map[string]time.Time),
		blockedIDs:    make(map[string]bool),
	}
}

// Start implements service.Service.Start.
func (h *Hysteria2Service) Start() error {
	h.clientInfo = h.apiClient.Describe()

	// Fetch node info.
	nodeInfo, err := h.apiClient.GetNodeInfo()
	if err != nil {
		return err
	}
	if nodeInfo.NodeType != "Hysteria2" {
		return fmt.Errorf("Hysteria2Service can only be used with Hysteria2 node, got %s", nodeInfo.NodeType)
	}
	if nodeInfo.Port == 0 {
		return errors.New("server port must > 0")
	}
	if nodeInfo.Hysteria2Config == nil {
		return errors.New("Hysteria2Config is nil in node info")
	}
	if h.config == nil || h.config.CertConfig == nil {
		return errors.New("CertConfig is required for Hysteria2")
	}

	h.nodeInfo = nodeInfo
	// Tag must be unique per logical node, even if multiple nodes share
	// the same listen IP and port. Include NodeID to keep limiter and
	// audit rule state isolated.
	h.tag = fmt.Sprintf("%s_%s_%d_%d", h.nodeInfo.NodeType, h.config.ListenIP, h.nodeInfo.Port, h.nodeInfo.NodeID)
	h.startAt = time.Now()

	// Initial user list.
	userInfo, err := h.apiClient.GetUserList()
	if err != nil {
		return err
	}
	h.syncUsers(userInfo)

	// Initial rule list.
	if !h.config.DisableGetRule && h.rules != nil {
		if ruleList, err := h.apiClient.GetNodeRule(); err != nil {
			h.logger.Printf("Get rule list filed: %s", err)
		} else if len(*ruleList) > 0 {
			if err := h.rules.UpdateRule(h.tag, *ruleList); err != nil {
				h.logger.Print(err)
			}
		}
		// Update exempt users
		if exemptUsers, err := h.apiClient.GetExemptUsers(); err != nil {
			h.logger.Printf("Get exempt users failed: %s", err)
		} else {
			h.rules.UpdateExemptUsers(exemptUsers)
		}
	}

	// Build Hysteria2 server.
	srv, err := h.newServer()
	if err != nil {
		return err
	}
	h.server = srv
	h.serve(srv, "start")

	// Apply Hysteria2 port hopping iptables rules for the initial node
	// configuration, if the panel enabled port hopping for this node.
	h.refreshPortHopRules()

	// Periodic tasks: user/traffic monitor, node monitor and optional cert
	// monitor for ACME (dns/http/tls) certificates.
	interval := time.Duration(h.config.UpdatePeriodic) * time.Second
	h.tasks = []periodicTask{
		{
			tag: h.tag,
			Periodic: &task.Periodic{
				Interval: interval,
				Execute:  h.userMonitor,
			},
		},
		{
			tag: "node monitor",
			Periodic: &task.Periodic{
				Interval: interval,
				Execute:  h.nodeMonitor,
			},
		},
	}

	// Check cert service in need (dns/http/tls auto-renewal)
	if h.nodeInfo.EnableTLS {
		h.tasks = append(h.tasks, periodicTask{
			tag: "cert monitor",
			Periodic: &task.Periodic{
				Interval: time.Duration(h.config.UpdatePeriodic) * time.Second * 60,
				Execute:  h.certMonitor,
			},
		})
	}

	for _, t := range h.tasks {
		go t.Start()
	}

	h.logger.Infof("Hysteria2 node started on %s:%d (hysteria core %s)", h.config.ListenIP, h.nodeInfo.Port, getHysteriaCoreVersion())
	return nil
}

// Close implements service.Service.Close.
func (h *Hysteria2Service) Close() error {
	// Best-effort cleanup of any iptables rules we previously installed for
	// Hysteria2 port hopping.
	h.reloadMu.Lock()
	if len(h.portHopRules) > 0 {
		deletePortHopIptablesRules(h.portHopRules, h.logger)
		h.portHopRules = nil
	}
	// 摘下来再关：serve 靠 h.server 是否还是自己来区分「我们关的」和「自己挂的」
	srv := h.server
	h.server = nil
	h.reloadMu.Unlock()

	for _, t := range h.tasks {
		if t.Periodic != nil {
			t.Periodic.Close()
		}
	}
	h.tasks = nil
	if srv != nil {
		return srv.Close()
	}
	return nil
}

// needsRebuild 报告是否该重试上一轮没走完的重建。退避未到就先不动。
func (h *Hysteria2Service) needsRebuild() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.rebuildPending && !time.Now().Before(h.rebuildRetryAt)
}

// setRebuildPending 置位或清除待重建。置位时按退避推后下一次重试：首次失败仍是
// 下一轮立刻重试，之后逐次翻倍到 rebuildRetryBackoffMax，清除时归零。
func (h *Hysteria2Service) setRebuildPending(pending bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !pending {
		h.rebuildPending = false
		h.rebuildRetryAt = time.Time{}
		h.rebuildBackoff = 0
		return
	}

	h.rebuildPending = true
	h.rebuildRetryAt = time.Now().Add(h.rebuildBackoff)
	next := 2 * h.rebuildBackoff
	if next == 0 {
		next = time.Duration(h.config.UpdatePeriodic) * time.Second
	}
	if next > rebuildRetryBackoffMax {
		next = rebuildRetryBackoffMax
	}
	h.rebuildBackoff = next
}

// serve 后台跑指定的 server。Serve 返回就意味着这份 server 不再收连接，但 reload
// 与 Close 都会主动关掉它，只有它仍挂在 h.server 上才算故障；reloadMu 保证这里读
// 到的是那些操作完成之后的状态。
func (h *Hysteria2Service) serve(srv server.Server, phase string) {
	go func() {
		err := srv.Serve()

		h.reloadMu.Lock()
		superseded := h.server != srv
		h.reloadMu.Unlock()
		if superseded {
			return
		}

		h.logger.Errorf("Hysteria2 serve stopped unexpectedly (%s): %v", phase, err)
		h.setRebuildPending(true)
	}()
}

// newServer 组装并创建 Hysteria2 server。buildServerConfig 里已经把 UDP 端口绑上，
// 而 server.NewServer 失败时不会关掉这个 conn，必须在这里关掉，否则端口一直被占、
// 后续重建再也绑不上。
func (h *Hysteria2Service) newServer() (server.Server, error) {
	cfg, err := h.buildServerConfig()
	if err != nil {
		return nil, err
	}
	srv, err := server.NewServer(cfg)
	if err != nil {
		cfg.Conn.Close()
		return nil, err
	}
	return srv, nil
}

// reloadNode replaces the in-memory node information and rebuilds the
// underlying Hysteria2 server so that changes from the panel (port, TLS,
// SNI, bandwidth, etc.) or renewed certificates take effect without
// restarting the whole ECYCloudNode process.
func (h *Hysteria2Service) reloadNode(nodeInfo *api.NodeInfo) error {
	if nodeInfo == nil {
		return nil
	}
	if nodeInfo.NodeType != "Hysteria2" {
		return fmt.Errorf("Hysteria2Service reloadNode: unexpected node type %s", nodeInfo.NodeType)
	}
	if nodeInfo.Port == 0 {
		return errors.New("server port must > 0")
	}
	if nodeInfo.Hysteria2Config == nil {
		return errors.New("Hysteria2Config is nil in node info")
	}
	if h.config == nil || h.config.CertConfig == nil {
		return errors.New("CertConfig is required for Hysteria2")
	}

	h.reloadMu.Lock()
	defer h.reloadMu.Unlock()

	oldInfo := h.nodeInfo
	h.nodeInfo = nodeInfo

	// Update port hopping iptables rules according to the latest node
	// configuration before we rebuild the underlying Hysteria2 server.
	h.updatePortHopRulesLocked()

	// Keep CertDomain in sync with the panel SNI when it was originally
	// derived from SNI/Host. If the user configured a custom CertDomain,
	// we respect it and do not override.
	if h.config.CertConfig != nil && h.nodeInfo.EnableTLS && !h.nodeInfo.EnableREALITY {
		sni := h.nodeInfo.SNI
		if sni == "" {
			sni = h.nodeInfo.Host
		}
		if sni != "" {
			cert := h.config.CertConfig
			var oldSNI, oldHost string
			if oldInfo != nil {
				oldSNI = oldInfo.SNI
				oldHost = oldInfo.Host
			}
			switch cert.CertMode {
			case "file":
				if cert.CertFile == "" && cert.KeyFile == "" {
					cert.CertDomain = sni
					cert.CertFile = "/etc/ECYCloudNode/cert/" + sni + ".cert"
					cert.KeyFile = "/etc/ECYCloudNode/cert/" + sni + ".key"
				} else if cert.CertDomain == "" || cert.CertDomain == oldSNI || cert.CertDomain == oldHost {
					cert.CertDomain = sni
				}
			case "dns", "http", "tls":
				if cert.CertDomain == "" || cert.CertDomain == oldSNI || cert.CertDomain == oldHost {
					cert.CertDomain = sni
				}
			}
		}
	}

	if h.server != nil {
		if err := h.server.Close(); err != nil {
			h.logger.Printf("Hysteria2 reload: failed to close old server: %v", err)
		}
		h.server = nil
	}

	srv, err := h.newServer()
	if err != nil {
		// nodeInfo 必须退回实际跑着的那份，端口跳跃规则跟着一起退，否则
		// syncUsers、nodeMonitor 与 iptables 都会按一份没生效的配置判断。
		h.nodeInfo = oldInfo
		h.updatePortHopRulesLocked()

		rebuilt := false
		// 重试与证书重载传进来的就是缓存那份配置，回滚等于把同一份再造一次
		if oldInfo != nil && oldInfo != nodeInfo {
			if rollback, rollbackErr := h.newServer(); rollbackErr != nil {
				h.logger.Errorf("Hysteria2 rollback to previous config failed: %v", rollbackErr)
			} else {
				h.server = rollback
				h.serve(rollback, "rollback")
				h.logger.Warnf("Hysteria2 reload failed, rolled back to previous config: %v", err)
				rebuilt = true
			}
		}
		h.setRebuildPending(!rebuilt)
		return err
	}
	h.server = srv
	h.setRebuildPending(false)
	h.serve(srv, "reload")

	h.logger.Infof("Hysteria2 node reloaded on %s:%d", h.config.ListenIP, h.nodeInfo.Port)
	return nil
}

// triggerRecovery attempts to recover from consecutive API communication failures
// (e.g., IP whitelist issues) by stopping and restarting all periodic tasks.
func (h *Hysteria2Service) triggerRecovery() {
	h.recoveryMutex.Lock()
	if h.recoveryInProgress {
		h.recoveryMutex.Unlock()
		h.logger.Warn("Recovery already in progress, skip duplicate trigger")
		return
	}
	h.recoveryInProgress = true
	h.recoveryMutex.Unlock()

	h.logger.Warn("Starting recovery procedure...")

	// Stop all periodic tasks
	for i := range h.tasks {
		if h.tasks[i].Periodic != nil {
			if err := h.tasks[i].Periodic.Close(); err != nil {
				h.logger.Errorf("Failed to stop %s task: %v", h.tasks[i].tag, err)
			}
		}
	}

	// Reset failure counter
	h.consecutiveFailures = 0

	// Restart periodic tasks after a short delay
	go func() {
		time.Sleep(5 * time.Second)
		h.logger.Info("Restarting periodic tasks...")
		for i := range h.tasks {
			h.logger.Printf("Restarting %s task", h.tasks[i].tag)
			go h.tasks[i].Start()
		}
		h.recoveryMutex.Lock()
		h.recoveryInProgress = false
		h.recoveryMutex.Unlock()
	}()
}

func getHysteriaCoreVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dep := range info.Deps {
		if dep.Path == "github.com/apernet/hysteria/core/v2" {
			if dep.Version != "" {
				return dep.Version
			}
			if dep.Replace != nil && dep.Replace.Version != "" {
				return dep.Replace.Version
			}
			break
		}
	}
	return "unknown"
}
