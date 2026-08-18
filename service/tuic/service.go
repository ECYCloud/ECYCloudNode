package tuic

import (
	"errors"
	"fmt"
	"runtime/debug"
	"time"

	box "github.com/sagernet/sing-box"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/task"

	"github.com/ECYCloud/ECYCloudNode/api"
	"github.com/ECYCloud/ECYCloudNode/common/limiter"
	"github.com/ECYCloud/ECYCloudNode/common/rule"
	"github.com/ECYCloud/ECYCloudNode/service"
	"github.com/ECYCloud/ECYCloudNode/service/controller"
)

var _ service.Service = (*TuicService)(nil)

// rebuildRetryBackoffMax 是待重建重试的退避上限。
const rebuildRetryBackoffMax = 30 * time.Minute

func New(apiClient api.API, cfg *controller.Config) *TuicService {
	clientInfo := apiClient.Describe()
	logger := log.NewEntry(log.StandardLogger()).WithFields(log.Fields{
		"Host": clientInfo.APIHost,
		"ID":   clientInfo.NodeID,
	})
	var globalChecker *limiter.GlobalDeviceChecker
	if cfg != nil {
		globalChecker = limiter.NewGlobalDeviceChecker(cfg.GlobalDeviceLimitConfig)
	}
	return &TuicService{
		apiClient:     apiClient,
		config:        cfg,
		logger:        logger,
		rules:         rule.New(),
		globalChecker: globalChecker,
		users:         make(map[string]userRecord),
		traffic:       make(map[string]*userTraffic),
		onlineIPs:     make(map[string]map[string]struct{}),
		ipLastActive:  make(map[string]map[string]time.Time),
	}
}

func (s *TuicService) Start() error {
	s.clientInfo = s.apiClient.Describe()

	nodeInfo, err := s.apiClient.GetNodeInfo()
	if err != nil {
		return err
	}
	if nodeInfo == nil || nodeInfo.NodeType != "Tuic" {
		return fmt.Errorf("TuicService can only be used with Tuic node, got %v", nodeInfo)
	}
	if nodeInfo.Port == 0 {
		return errors.New("server port must > 0")
	}
	if s.config == nil || s.config.CertConfig == nil {
		return errors.New("CertConfig is required for TUIC")
	}
	if nodeInfo.TuicConfig == nil {
		nodeInfo.TuicConfig = &api.TuicConfig{}
	}

	s.nodeInfo = nodeInfo
	// Ensure tag is unique per TUIC node by embedding NodeID so that
	// limiter and rule manager state remain per-node, even when
	// multiple TUIC nodes share the same listen endpoint.
	s.tag = fmt.Sprintf("%s_%s_%d_%d", s.nodeInfo.NodeType, s.config.ListenIP, s.nodeInfo.Port, s.nodeInfo.NodeID)
	s.startAt = time.Now()
	s.inboundTag = s.tag

	userInfo, err := s.apiClient.GetUserList()
	if err != nil {
		return err
	}
	if userInfo == nil || len(*userInfo) == 0 {
		s.logger.Warn("No users found for TUIC node, authentication may fail")
	} else {
		s.logger.Infof("Syncing %d users for TUIC node", len(*userInfo))
		// Log first user UUID (partial) for verification at info level so user can confirm credentials
		if len(*userInfo) > 0 {
			firstUser := (*userInfo)[0]
			uuidPreview := firstUser.UUID
			if len(uuidPreview) > 8 {
				uuidPreview = uuidPreview[:8] + "..."
			}
			s.logger.Infof("First TUIC user from panel: UID=%d, UUID=%s, HasPassword=%v", firstUser.UID, uuidPreview, firstUser.Passwd != "")
		}
	}
	s.syncUsers(userInfo)

	// Initial rule list.
	if !s.config.DisableGetRule && s.rules != nil {
		if ruleList, err := s.apiClient.GetNodeRule(); err != nil {
			s.logger.Printf("Get rule list filed: %s", err)
		} else if len(*ruleList) > 0 {
			if err := s.rules.UpdateRule(s.tag, *ruleList); err != nil {
				s.logger.Print(err)
			}
		}
		// Update exempt users
		if exemptUsers, err := s.apiClient.GetExemptUsers(); err != nil {
			s.logger.Printf("Get exempt users failed: %s", err)
		} else {
			s.rules.UpdateExemptUsers(exemptUsers)
		}
	}

	boxInstance, _, err := s.buildSingBox()
	if err != nil {
		return err
	}
	s.box = boxInstance
	s.startBox(boxInstance, "start")

	interval := time.Duration(s.config.UpdatePeriodic) * time.Second
	s.tasks = []periodicTask{
		{
			tag: s.tag,
			Periodic: &task.Periodic{
				Interval: interval,
				Execute:  s.userMonitor,
			},
		},
		{
			tag: "node monitor",
			Periodic: &task.Periodic{
				Interval: interval,
				Execute:  s.nodeMonitor,
			},
		},
	}

	if s.nodeInfo.EnableTLS {
		s.tasks = append(s.tasks, periodicTask{
			tag: "cert monitor",
			Periodic: &task.Periodic{
				Interval: time.Duration(s.config.UpdatePeriodic) * time.Second * 60,
				Execute:  s.certMonitor,
			},
		})
	}

	for _, t := range s.tasks {
		go t.Start()
	}

	s.logger.Infof("TUIC node started on %s:%d (sing-box %s)", s.config.ListenIP, s.nodeInfo.Port, getSingBoxVersion())
	return nil
}

func (s *TuicService) Close() error {
	// 摘下来再关：startBox 靠 s.box 是否还是自己来区分「我们关的」和「它自己没起来」
	s.reloadMu.Lock()
	instance := s.box
	s.box = nil
	s.reloadMu.Unlock()

	for _, t := range s.tasks {
		if t.Periodic != nil {
			t.Periodic.Close()
		}
	}
	s.tasks = nil
	if instance != nil {
		return instance.Close()
	}
	return nil
}

// currentNodeInfo 读取当前节点信息。nodeMonitor、userMonitor 与 certMonitor 是
// 三个独立 goroutine，而 reloadNode 会在 s.mu 下整体替换它。
func (s *TuicService) currentNodeInfo() *api.NodeInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nodeInfo
}

// awaitingRebuild 报告节点是否已置位待重建，不看退避。
func (s *TuicService) awaitingRebuild() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rebuildPending
}

// needsRebuild 报告是否该重试上一轮没走完的重建。退避未到就先不动。
func (s *TuicService) needsRebuild() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rebuildPending && !time.Now().Before(s.rebuildRetryAt)
}

// setRebuildPending 置位或清除待重建。置位时按退避推后下一次重试：首次失败仍是
// 下一轮立刻重试，之后逐次翻倍到 rebuildRetryBackoffMax，清除时归零。
func (s *TuicService) setRebuildPending(pending bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !pending {
		s.rebuildPending = false
		s.rebuildRetryAt = time.Time{}
		s.rebuildBackoff = 0
		return
	}

	s.rebuildPending = true
	s.rebuildRetryAt = time.Now().Add(s.rebuildBackoff)
	next := 2 * s.rebuildBackoff
	if next == 0 {
		next = time.Duration(s.config.UpdatePeriodic) * time.Second
	}
	if next > rebuildRetryBackoffMax {
		next = rebuildRetryBackoffMax
	}
	s.rebuildBackoff = next
}

// startBox 后台启动 box。sing-box 的入站在 Start 才绑定端口，端口被占之类的错误
// 不会在构造阶段暴露，因此启动失败必须重新置位待重建；但这个 goroutine 可能晚到，
// 只有它启动的仍是当前 box 才算故障，reloadMu 保证读到的是 reload 之后的状态。
func (s *TuicService) startBox(instance *box.Box, phase string) {
	go func() {
		err := instance.Start()
		if err == nil {
			return
		}

		s.reloadMu.Lock()
		superseded := s.box != instance
		s.reloadMu.Unlock()
		if superseded {
			return
		}

		s.logger.Errorf("TUIC box start error (%s): %v", phase, err)
		s.setRebuildPending(true)
	}()
}

// reloadNode replaces in-memory node information and rebuilds the underlying
// sing-box TUIC instance so that changes from the panel (port, TLS/SNI,
// congestion control, etc.) and renewed certificates take effect without
// restarting the whole ECYCloudNode process.
func (s *TuicService) reloadNode(nodeInfo *api.NodeInfo) error {
	if nodeInfo == nil {
		return nil
	}
	if nodeInfo.NodeType != "Tuic" {
		return fmt.Errorf("TuicService reloadNode: unexpected node type %s", nodeInfo.NodeType)
	}
	if nodeInfo.Port == 0 {
		return errors.New("server port must > 0")
	}
	if s.config == nil || s.config.CertConfig == nil {
		return errors.New("CertConfig is required for TUIC")
	}
	if nodeInfo.TuicConfig == nil {
		nodeInfo.TuicConfig = &api.TuicConfig{}
	}

	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	// nodeInfo 同时被 userMonitor 读取（syncUsers 取 SpeedLimit），必须与其同锁
	s.mu.Lock()
	oldInfo := s.nodeInfo
	s.nodeInfo = nodeInfo
	s.mu.Unlock()

	// Keep CertDomain in sync with the panel SNI when originally derived from
	// SNI/Host.
	if s.config.CertConfig != nil && s.nodeInfo.EnableTLS && !s.nodeInfo.EnableREALITY {
		sni := s.nodeInfo.SNI
		if sni == "" {
			sni = s.nodeInfo.Host
		}
		if sni != "" {
			cert := s.config.CertConfig
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

	if s.box != nil {
		if err := s.box.Close(); err != nil {
			s.logger.Printf("TUIC reload: failed to close old box: %v", err)
		}
		s.box = nil
	}

	boxInstance, inboundTag, err := s.buildSingBox()
	if err != nil {
		// nodeInfo 必须退回实际跑着的那份，否则 syncUsers 与 nodeMonitor 的
		// DeepEqual 都会按一份没生效的配置判断。
		s.mu.Lock()
		s.nodeInfo = oldInfo
		s.mu.Unlock()

		rebuilt := false
		// 重试与证书重载传进来的就是缓存那份配置，回滚等于把同一份再造一次
		if oldInfo != nil && oldInfo != nodeInfo {
			if rollback, rollbackTag, rollbackErr := s.buildSingBox(); rollbackErr != nil {
				s.logger.Errorf("TUIC rollback to previous config failed: %v", rollbackErr)
			} else {
				s.box = rollback
				s.inboundTag = rollbackTag
				s.startBox(rollback, "rollback")
				s.logger.Warnf("TUIC reload failed, rolled back to previous config: %v", err)
				rebuilt = true
			}
		}
		s.setRebuildPending(!rebuilt)
		return err
	}
	s.box = boxInstance
	s.inboundTag = inboundTag
	s.setRebuildPending(false)
	s.startBox(boxInstance, "reload")

	s.logger.Infof("TUIC node reloaded on %s:%d", s.config.ListenIP, s.nodeInfo.Port)
	return nil
}

// triggerRecovery attempts to recover from consecutive API communication failures
// (e.g., IP whitelist issues) by stopping and restarting all periodic tasks.
func (s *TuicService) triggerRecovery() {
	s.recoveryMutex.Lock()
	if s.recoveryInProgress {
		s.recoveryMutex.Unlock()
		s.logger.Warn("Recovery already in progress, skip duplicate trigger")
		return
	}
	s.recoveryInProgress = true
	s.recoveryMutex.Unlock()

	s.logger.Warn("Starting recovery procedure...")

	// Stop all periodic tasks
	for i := range s.tasks {
		if s.tasks[i].Periodic != nil {
			if err := s.tasks[i].Periodic.Close(); err != nil {
				s.logger.Errorf("Failed to stop %s task: %v", s.tasks[i].tag, err)
			}
		}
	}

	// Reset failure counter
	s.consecutiveFailures = 0

	// Restart periodic tasks after a short delay
	go func() {
		time.Sleep(5 * time.Second)
		s.logger.Info("Restarting periodic tasks...")
		for i := range s.tasks {
			s.logger.Printf("Restarting %s task", s.tasks[i].tag)
			go s.tasks[i].Start()
		}
		s.recoveryMutex.Lock()
		s.recoveryInProgress = false
		s.recoveryMutex.Unlock()
	}()
}

func getSingBoxVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dep := range info.Deps {
		if dep.Path == "github.com/sagernet/sing-box" {
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
