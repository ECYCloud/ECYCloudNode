package anytls

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
	"github.com/ECYCloud/ECYCloudNode/common/unlockcheck"
	"github.com/ECYCloud/ECYCloudNode/service"
	"github.com/ECYCloud/ECYCloudNode/service/controller"
)

var _ service.Service = (*AnyTLSService)(nil)

// rebuildRetryBackoffMax 是待重建重试的退避上限。
const rebuildRetryBackoffMax = 30 * time.Minute

func New(apiClient api.API, cfg *controller.Config) *AnyTLSService {
	clientInfo := apiClient.Describe()
	logger := log.NewEntry(log.StandardLogger()).WithFields(log.Fields{
		"Host": clientInfo.APIHost,
		"ID":   clientInfo.NodeID,
	})
	var globalChecker *limiter.GlobalDeviceChecker
	if cfg != nil {
		globalChecker = limiter.NewGlobalDeviceChecker(cfg.GlobalDeviceLimitConfig)
	}
	return &AnyTLSService{
		apiClient:      apiClient,
		config:         cfg,
		logger:         logger,
		rules:          rule.New(),
		globalChecker:  globalChecker,
		users:          make(map[string]userRecord),
		onlineSlots:    make(map[string]map[string]struct{}),
		slotLastActive: make(map[string]map[string]time.Time),
	}
}

func (s *AnyTLSService) Start() error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	s.reloadMu.Lock()
	s.closed = false
	s.generation++
	generation := s.generation
	s.reloadMu.Unlock()
	s.clientInfo = s.apiClient.Describe()
	if s.config != nil && !s.config.DisableUploadTraffic {
		if err := s.apiClient.PrepareTraffic(); err != nil {
			return err
		}
	}

	nodeInfo, err := s.apiClient.GetNodeInfo()
	if err != nil {
		return err
	}
	if nodeInfo == nil || nodeInfo.NodeType != "AnyTLS" {
		return fmt.Errorf("AnyTLSService can only be used with AnyTLS node, got %v", nodeInfo)
	}
	if nodeInfo.Port == 0 {
		return errors.New("server port must > 0")
	}
	if s.config == nil || s.config.CertConfig == nil {
		return errors.New("CertConfig is required for AnyTLS")
	}
	if nodeInfo.AnyTLSConfig == nil {
		nodeInfo.AnyTLSConfig = &api.AnyTLSConfig{}
	}

	s.nodeInfo = nodeInfo
	// Ensure tag is unique per AnyTLS node by embedding NodeID so that
	// online-user and audit data do not mix across nodes sharing the
	// same IP/port combination.
	s.tag = fmt.Sprintf("%s_%s_%d_%d", s.nodeInfo.NodeType, s.config.ListenIP, s.nodeInfo.Port, s.nodeInfo.NodeID)
	s.startAt = time.Now()
	s.inboundTag = s.tag

	userInfo, err := s.apiClient.GetUserList()
	if err != nil {
		return err
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
	s.reloadMu.Lock()
	s.box = boxInstance
	s.setRebuildPending(s.startBox(boxInstance, "start") != nil)
	s.reloadMu.Unlock()

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

	s.tasks = append(s.tasks, periodicTask{
		tag:      "unlock check",
		Periodic: unlockcheck.NewTask(s.apiClient, s.nodeInfo.NodeID, s.logger),
	})

	for _, t := range s.tasks {
		execute := t.Execute
		t.Execute = func() error {
			s.lifecycleMu.RLock()
			defer s.lifecycleMu.RUnlock()
			s.reloadMu.Lock()
			closed := s.closed || generation != s.generation
			s.reloadMu.Unlock()
			if closed {
				return errors.New("AnyTLS service is closed")
			}
			return execute()
		}
		go t.Start()
	}

	s.logger.Infof("AnyTLS node started on %s:%d (sing-box %s)", s.config.ListenIP, s.nodeInfo.Port, getSingBoxVersion())
	return nil
}

func (s *AnyTLSService) Close() error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	s.closed = true
	instance := s.box
	s.box = nil
	front := s.frontListener
	s.frontListener = nil

	for _, t := range s.tasks {
		if t.Periodic != nil {
			t.Periodic.Close()
		}
	}
	s.tasks = nil
	if front != nil {
		front.Close()
	}
	var closeErr error
	if instance != nil {
		closeErr = instance.Close()
	}
	return errors.Join(closeErr, s.apiClient.CloseTraffic())
}

// currentNodeInfo 读取当前节点信息。nodeMonitor、userMonitor 与 certMonitor 是
// 三个独立 goroutine，而 reloadNode 会在 s.mu 下整体替换它。
func (s *AnyTLSService) currentNodeInfo() *api.NodeInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nodeInfo
}

// awaitingRebuild 报告节点是否已置位待重建，不看退避。
func (s *AnyTLSService) awaitingRebuild() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rebuildPending
}

// needsRebuild 报告是否该重试上一轮没走完的重建。退避未到就先不动。
func (s *AnyTLSService) needsRebuild() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rebuildPending && !time.Now().Before(s.rebuildRetryAt)
}

// setRebuildPending 置位或清除待重建。置位时按退避推后下一次重试：首次失败仍是
// 下一轮立刻重试，之后逐次翻倍到 rebuildRetryBackoffMax，清除时归零。
func (s *AnyTLSService) setRebuildPending(pending bool) {
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

func (s *AnyTLSService) startBox(instance *box.Box, phase string) error {
	err := instance.Start()
	if err != nil {
		s.logger.Errorf("AnyTLS box start error (%s): %v", phase, err)
	}
	return err
}

// reloadNode replaces in-memory node information and rebuilds the underlying
// sing-box AnyTLS instance so that changes from the panel (port, TLS/SNI,
// padding options, etc.) and renewed certificates take effect without
// restarting the whole ECYCloudNode process.
func (s *AnyTLSService) reloadNode(nodeInfo *api.NodeInfo) error {
	if nodeInfo == nil {
		return nil
	}
	if nodeInfo.NodeType != "AnyTLS" {
		return fmt.Errorf("AnyTLSService reloadNode: unexpected node type %s", nodeInfo.NodeType)
	}
	if nodeInfo.Port == 0 {
		return errors.New("server port must > 0")
	}
	if s.config == nil || s.config.CertConfig == nil {
		return errors.New("CertConfig is required for AnyTLS")
	}
	if nodeInfo.AnyTLSConfig == nil {
		nodeInfo.AnyTLSConfig = &api.AnyTLSConfig{}
	}

	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	if s.closed {
		return errors.New("AnyTLS service is closed")
	}

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

	if s.frontListener != nil {
		s.frontListener.Close()
		s.frontListener = nil
	}
	if s.box != nil {
		if err := s.box.Close(); err != nil {
			s.logger.Printf("AnyTLS reload: failed to close old box: %v", err)
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
				s.logger.Errorf("AnyTLS rollback to previous config failed: %v", rollbackErr)
			} else {
				s.box = rollback
				s.inboundTag = rollbackTag
				rebuilt = s.startBox(rollback, "rollback") == nil
				if rebuilt {
					s.logger.Warnf("AnyTLS reload failed, rolled back to previous config: %v", err)
				}
			}
		}
		s.setRebuildPending(!rebuilt)
		return err
	}
	s.box = boxInstance
	s.inboundTag = inboundTag
	s.setRebuildPending(s.startBox(boxInstance, "reload") != nil)

	s.logger.Infof("AnyTLS node reloaded on %s:%d", s.config.ListenIP, s.nodeInfo.Port)
	return nil
}

// triggerRecovery attempts to recover from consecutive API communication failures
// (e.g., IP whitelist issues) by stopping and restarting all periodic tasks.
func (s *AnyTLSService) triggerRecovery() {
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
	tasks := s.tasks
	go func() {
		time.Sleep(5 * time.Second)
		s.logger.Info("Restarting periodic tasks...")
		for i := range tasks {
			s.logger.Printf("Restarting %s task", tasks[i].tag)
			go tasks[i].Start()
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
