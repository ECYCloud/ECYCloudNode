package anytls

import (
	"net"
	"reflect"
	"time"

	"github.com/sagernet/sing-box/option"
	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"

	"github.com/ECYCloud/ECYCloudNode/api"
	"github.com/ECYCloud/ECYCloudNode/common/limiter"
	"github.com/ECYCloud/ECYCloudNode/common/serverstatus"
)

func (s *AnyTLSService) syncUsers(userInfo *[]api.UserInfo) {
	if userInfo == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	newUsers := make(map[string]userRecord, len(*userInfo))
	authUsers := make([]option.AnyTLSUser, 0, len(*userInfo)*2)
	newRateLimiters := make(map[string]*rate.Limiter)

	var nodeLimit uint64
	if s.nodeInfo != nil {
		nodeLimit = s.nodeInfo.SpeedLimit
	}

	for _, u := range *userInfo {
		keys := []string{u.UUID, u.Passwd}
		rec := userRecord{
			UID:         u.UID,
			Email:       u.Email,
			DeviceLimit: u.DeviceLimit,
			SpeedLimit:  u.SpeedLimit,
		}

		limit := determineRate(nodeLimit, u.SpeedLimit)
		var limiter *rate.Limiter
		if limit > 0 {
			// Try to reuse an existing limiter if present.
			for _, k := range keys {
				if k == "" {
					continue
				}
				if old, ok := s.rateLimiters[k]; ok && old != nil {
					old.SetLimit(rate.Limit(limit))
					old.SetBurst(int(limit))
					limiter = old
					break
				}
			}
			if limiter == nil {
				limiter = rate.NewLimiter(rate.Limit(limit), int(limit))
			}
		}

		for _, k := range keys {
			if k == "" {
				continue
			}
			if _, ok := newUsers[k]; !ok {
				newUsers[k] = rec
			}
			if limiter != nil {
				newRateLimiters[k] = limiter
			}
			if _, ok := s.traffic[k]; !ok {
				s.traffic[k] = &userTraffic{}
			}
		}

		if u.UUID != "" {
			authUsers = append(authUsers, option.AnyTLSUser{
				Name:     u.UUID,
				Password: u.UUID,
			})
		}
		if u.Passwd != "" && u.Passwd != u.UUID {
			authUsers = append(authUsers, option.AnyTLSUser{
				Name:     u.Passwd,
				Password: u.Passwd,
			})
		}
	}

	s.users = newUsers
	s.authUsers = authUsers
	s.rateLimiters = newRateLimiters

	for uuid := range s.onlineIPs {
		if _, ok := newUsers[uuid]; !ok {
			delete(s.onlineIPs, uuid)
		}
	}
	// Clean ipLastActive records for removed users
	for uuid := range s.ipLastActive {
		if _, ok := newUsers[uuid]; !ok {
			delete(s.ipLastActive, uuid)
		}
	}
}

// hasUnbuiltAuthUser 报告是否存在运行中的 inbound 还不认识的凭据。
func (s *AnyTLSService) hasUnbuiltAuthUser() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.authUsers {
		if _, ok := s.builtAuthUsers[u.Name]; !ok {
			return true
		}
	}
	return false
}

func (s *AnyTLSService) addTraffic(uuid string, up, down int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.traffic[uuid]
	if !ok {
		t = &userTraffic{}
		s.traffic[uuid] = t
	}
	t.Upload += up
	t.Download += down

	// Note: We don't update onlineIPs here because we don't have the IP address.
	// The IP is updated in Read/Write methods via updateOnlineIP().
}

func (s *AnyTLSService) allowConnection(uuid, ip string) bool {
	host := ip
	if host != "" {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}
	if host == "" {
		host = "unknown"
	}

	s.mu.Lock()

	user, ok := s.users[uuid]
	if !ok {
		s.mu.Unlock()
		return false
	}

	ips, ok := s.onlineIPs[uuid]
	if !ok {
		ips = make(map[string]struct{})
		s.onlineIPs[uuid] = ips
	}

	// Initialize ipLastActive map for this user if not exists
	activeMap, ok := s.ipLastActive[uuid]
	if !ok {
		activeMap = make(map[string]time.Time)
		s.ipLastActive[uuid] = activeMap
	}

	allowed, granted := limiter.AdmitDeviceIP(ips, activeMap, host, user.UID, user.DeviceLimit)
	s.mu.Unlock()
	if !allowed {
		s.logger.WithFields(log.Fields{
			"uid":         user.UID,
			"deviceLimit": user.DeviceLimit,
			"remote":      ip,
		}).Warn("AnyTLS user exceeded device limit")
		return false
	}

	// 全局（跨节点）限制：涉及 Redis 访问，必须在锁外执行
	if !s.globalChecker.Allow(user.UID, host, user.DeviceLimit, granted) {
		s.mu.Lock()
		delete(s.onlineIPs[uuid], host)
		if am, ok := s.ipLastActive[uuid]; ok {
			delete(am, host)
		}
		s.mu.Unlock()
		s.logger.WithFields(log.Fields{
			"uid":         user.UID,
			"deviceLimit": user.DeviceLimit,
			"remote":      ip,
		}).Warn("AnyTLS user exceeded global device limit")
		return false
	}

	return true
}

// updateOnlineIP 仅刷新仍持有名额的 IP；已被超限踢出的禁止靠流量抢回。
func (s *AnyTLSService) updateOnlineIP(uuid string, addr net.Addr) {
	if addr == nil {
		return
	}

	remote := addr.String()
	host := remote
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if ipSet, exists := s.onlineIPs[uuid]; exists {
		if _, online := ipSet[host]; online {
			if activeMap, ok := s.ipLastActive[uuid]; ok {
				activeMap[host] = time.Now()
			}
		}
	}
}

// updateOnlineIPSimple 仅刷新仍持有名额的 IP（UDP 路径，host 已解析）。
func (s *AnyTLSService) updateOnlineIPSimple(uuid, host string) {
	if host == "" || uuid == "" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if ipSet, exists := s.onlineIPs[uuid]; exists {
		if _, online := ipSet[host]; online {
			if activeMap, ok := s.ipLastActive[uuid]; ok {
				activeMap[host] = time.Now()
			}
		}
	}
}

func (s *AnyTLSService) collectUsage() ([]api.UserTraffic, []api.OnlineUser, map[string]userTraffic) {
	s.mu.Lock()
	defer s.mu.Unlock()

	snapshot := make(map[string]userTraffic)
	var uts []api.UserTraffic
	for uuid, t := range s.traffic {
		user, ok := s.users[uuid]
		if !ok {
			continue
		}
		if t.Upload == 0 && t.Download == 0 {
			continue
		}
		snapshot[uuid] = userTraffic{
			Upload:   t.Upload,
			Download: t.Download,
		}
		uts = append(uts, api.UserTraffic{
			UID:      user.UID,
			Email:    user.Email,
			Upload:   t.Upload,
			Download: t.Download,
		})
		t.Upload = 0
		t.Download = 0
	}

	// 先按活跃时间清理过期 IP，再收集在线用户。
	// 整表清空会导致每个上报周期设备名额被重新抢占，使设备限制形同虚设；
	// 活跃连接会通过流量事件持续刷新 ipLastActive，从而稳定持有名额。
	now := time.Now()
	for uuid, activeMap := range s.ipLastActive {
		for ip, last := range activeMap {
			if now.Sub(last) > limiter.OnlineIPExpiry {
				delete(activeMap, ip)
				if ipSet, ok := s.onlineIPs[uuid]; ok {
					delete(ipSet, ip)
				}
			}
		}
		if len(activeMap) == 0 {
			delete(s.ipLastActive, uuid)
			delete(s.onlineIPs, uuid)
		}
	}

	var online []api.OnlineUser
	for uuid, ipSet := range s.onlineIPs {
		user, ok := s.users[uuid]
		if !ok {
			continue
		}
		for ip := range ipSet {
			online = append(online, api.OnlineUser{UID: user.UID, IP: ip})
		}
	}

	return uts, online, snapshot
}

func (s *AnyTLSService) restoreTraffic(snapshot map[string]userTraffic) {
	if len(snapshot) == 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for uuid, snap := range snapshot {
		counter, ok := s.traffic[uuid]
		if !ok || counter == nil {
			counter = &userTraffic{}
			s.traffic[uuid] = counter
		}
		counter.Upload += snap.Upload
		counter.Download += snap.Download
	}
}

func (s *AnyTLSService) userMonitor() error {
	if time.Since(s.startAt) < time.Duration(s.config.UpdatePeriodic)*time.Second {
		return nil
	}

	CPU, Mem, Disk, Uptime, err := serverstatus.GetSystemInfo()
	if err != nil {
		s.logger.Print(err)
	} else {
		if err = s.apiClient.ReportNodeStatus(&api.NodeStatus{CPU: CPU, Mem: Mem, Disk: Disk, Uptime: Uptime}); err != nil {
			s.logger.Print(err)
		}
	}

	usersChanged := true
	newUserInfo, err := s.apiClient.GetUserList()
	if err != nil {
		if err.Error() == api.UserNotModified {
			usersChanged = false
			// Reset failure counter on successful "not modified" response
			s.consecutiveFailures = 0
		} else {
			s.logger.Print(err)
			// Track consecutive API failures for recovery
			if api.IsAPIFailure(err) {
				s.consecutiveFailures++
				s.lastFailureTime = time.Now()
				s.logger.Warnf("API communication failure detected (%d/%d)", s.consecutiveFailures, api.MaxConsecutiveFailures)
				if s.consecutiveFailures >= api.MaxConsecutiveFailures {
					s.logger.Errorf("Consecutive API failures reached threshold (%d), triggering service recovery...", s.consecutiveFailures)
					s.triggerRecovery()
				}
			}
			return nil
		}
	}
	if s.consecutiveFailures != 0 {
		s.consecutiveFailures = 0
	}
	if usersChanged {
		s.syncUsers(newUserInfo)
		// 被删用户已由 allowConnection 拦住，但新增凭据过不了 sing-box 的认证，
		// 必须重建 inbound 才能连上；已置位待重建时交给 nodeMonitor 按退避重试，
		// 那次重建同样会带上最新凭据，这里再触发一次只会绕开退避。
		if s.hasUnbuiltAuthUser() && !s.awaitingRebuild() {
			if err := s.reloadNode(s.currentNodeInfo()); err != nil {
				s.logger.Errorf("AnyTLS rebuild for new users failed: %v", err)
			}
		}
	}

	// Check Rule
	if !s.config.DisableGetRule && s.rules != nil {
		if ruleList, err := s.apiClient.GetNodeRule(); err != nil {
			if err.Error() != api.RuleNotModified {
				s.logger.Printf("Get rule list filed: %s", err)
			}
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

	userTraffic, onlineUsers, snapshot := s.collectUsage()
	if len(userTraffic) > 0 && !s.config.DisableUploadTraffic {
		if err = s.apiClient.ReportUserTraffic(&userTraffic); err != nil {
			s.logger.Print(err)
			// Restore counters so traffic is not lost and can be retried.
			s.restoreTraffic(snapshot)
		}
	}
	if err = s.apiClient.ReportNodeOnlineUsers(&onlineUsers); err != nil {
		s.logger.Print(err)
	}
	if kicks := limiter.TakeDeviceKicks(); len(kicks) > 0 {
		if err = s.apiClient.ReportKickedUsers(&kicks); err != nil {
			s.logger.Print(err)
		}
	}

	// Report Illegal user
	if s.rules != nil {
		if detectResult, err := s.rules.GetDetectResult(s.tag); err != nil {
			s.logger.Print(err)
		} else if len(*detectResult) > 0 {
			if err = s.apiClient.ReportIllegal(detectResult); err != nil {
				s.logger.Print(err)
			} else {
				s.logger.Printf("Report %d illegal behaviors", len(*detectResult))
			}
		}
	}

	return nil
}

// nodeMonitor watches for AnyTLS node configuration changes from the panel
// (port, TLS/SNI, AnyTLS-specific options, etc.) and hot-reloads the sing-box
// instance when a change is detected.
func (s *AnyTLSService) nodeMonitor() error {
	if time.Since(s.startAt) < time.Duration(s.config.UpdatePeriodic)*time.Second {
		return nil
	}

	nodeInfo, err := s.apiClient.GetNodeInfo()
	if err != nil {
		if err.Error() == api.NodeNotModified {
			// Reset failure counter on successful "not modified" response
			s.consecutiveFailures = 0
			// 304 不带配置，上一轮重建没走完时只能拿缓存的 nodeInfo 重试
			if s.needsRebuild() {
				if err := s.reloadNode(s.currentNodeInfo()); err != nil {
					s.logger.Printf("AnyTLS node rebuild retry failed: %v", err)
				}
			}
			return nil
		}
		s.logger.Print(err)
		// Track consecutive API failures for recovery
		if api.IsAPIFailure(err) {
			s.consecutiveFailures++
			s.lastFailureTime = time.Now()
			s.logger.Warnf("API communication failure detected (%d/%d)", s.consecutiveFailures, api.MaxConsecutiveFailures)

			// Check if we should trigger auto-recovery
			if s.consecutiveFailures >= api.MaxConsecutiveFailures {
				s.logger.Errorf("Consecutive API failures reached threshold (%d), triggering service recovery...", s.consecutiveFailures)
				s.triggerRecovery()
			}
		}
		return nil
	}

	if s.consecutiveFailures != 0 {
		s.consecutiveFailures = 0
	}

	if nodeInfo == nil || nodeInfo.NodeType != "AnyTLS" {
		if s.logger != nil {
			if nodeInfo == nil {
				s.logger.Warnf("AnyTLS node monitor: unexpected node info: nil")
			} else {
				s.logger.Warnf("AnyTLS node monitor: unexpected node info: type=%s id=%d port=%d", nodeInfo.NodeType, nodeInfo.NodeID, nodeInfo.Port)
			}
		}
		return nil
	}

	// Same as TUIC/Hysteria2: protect against noisy panel-side metadata updates
	// that change the ETag without altering the actual AnyTLS node configuration
	// by skipping reload when the effective NodeInfo is unchanged.
	if current := s.currentNodeInfo(); current != nil && !s.needsRebuild() && reflect.DeepEqual(current, nodeInfo) {
		return nil
	}

	if err := s.reloadNode(nodeInfo); err != nil {
		s.logger.Printf("AnyTLS node reload failed: %v", err)
	}

	return nil
}

func determineRate(nodeLimit, userLimit uint64) (limit uint64) {
	if nodeLimit == 0 || userLimit == 0 {
		if nodeLimit > userLimit {
			return nodeLimit
		} else if nodeLimit < userLimit {
			return userLimit
		}
		return 0
	}

	if nodeLimit > userLimit {
		return userLimit
	} else if nodeLimit < userLimit {
		return nodeLimit
	}
	return nodeLimit
}
