package controller

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"

	"github.com/ECYCloud/ECYCloudNode/api"
	"github.com/ECYCloud/ECYCloudNode/app/mydispatcher"
	"github.com/ECYCloud/ECYCloudNode/common/limiter"
	"github.com/ECYCloud/ECYCloudNode/common/unlockcheck"
	"github.com/ECYCloud/ECYCloudNode/common/mylego"
	"github.com/ECYCloud/ECYCloudNode/common/rule"
	"github.com/ECYCloud/ECYCloudNode/common/serverstatus"
)

type LimitInfo struct {
	end               int64
	currentSpeedLimit int
	originSpeedLimit  uint64
}

type Controller struct {
	server       *core.Instance
	config       *Config
	clientInfo   api.ClientInfo
	apiClient    api.API
	nodeInfo     *api.NodeInfo
	Tag          string
	userList     *[]api.UserInfo
	tasks        []periodicTask
	limitedUsers map[api.UserInfo]LimitInfo
	warnedUsers  map[api.UserInfo]int
	panelType    string
	ibm          inbound.Manager
	obm          outbound.Manager
	stm          stats.Manager
	pm           policy.Manager
	router       routing.Router
	dispatcher   *mydispatcher.DefaultDispatcher
	startAt      time.Time
	logger       *log.Entry
	// Unlock check related fields
	unlockChecker       *unlockcheck.Checker
	lastUnlockCheckTime time.Time
	unlockCheckMutex    sync.Mutex
	// Recovery tracking for IP whitelist / connectivity issues
	consecutiveFailures int
	lastFailureTime     time.Time
	recoveryMutex       sync.Mutex
	recoveryInProgress  bool
}

type periodicTask struct {
	tag string
	*task.Periodic
}

// New return a Controller service with default parameters.
func New(server *core.Instance, api api.API, config *Config, panelType string) *Controller {
	clientInfo := api.Describe()
	logger := log.NewEntry(log.StandardLogger()).WithFields(log.Fields{
		"Host": clientInfo.APIHost,
		"ID":   clientInfo.NodeID,
	})
	// Try to get custom dispatcher; tests may not register it, so provide a safe fallback.
	var md *mydispatcher.DefaultDispatcher
	if f := server.GetFeature(mydispatcher.Type()); f != nil {
		if d, ok := f.(*mydispatcher.DefaultDispatcher); ok {
			md = d
		}
	}
	if md == nil {
		md = &mydispatcher.DefaultDispatcher{
			Limiter:     limiter.New(),
			RuleManager: rule.New(),
		}
	}

	// Get the router for adding dynamic routing rules
	var rt routing.Router
	if f := server.GetFeature(routing.RouterType()); f != nil {
		if r, ok := f.(routing.Router); ok {
			rt = r
		}
	}

	controller := &Controller{
		server:     server,
		config:     config,
		apiClient:  api,
		panelType:  panelType,
		ibm:        server.GetFeature(inbound.ManagerType()).(inbound.Manager),
		obm:        server.GetFeature(outbound.ManagerType()).(outbound.Manager),
		stm:        server.GetFeature(stats.ManagerType()).(stats.Manager),
		pm:         server.GetFeature(policy.ManagerType()).(policy.Manager),
		router:     rt,
		dispatcher: md,
		startAt:    time.Now(),
		logger:     logger,
	}

	return controller
}

// Start implement the Start() function of the service interface
func (c *Controller) Start() error {
	c.clientInfo = c.apiClient.Describe()
	// First fetch Node Info
	newNodeInfo, err := c.apiClient.GetNodeInfo()
	if err != nil {
		return err
	}
	if newNodeInfo.Port == 0 {
		return errors.New("server port must > 0")
	}
	c.nodeInfo = newNodeInfo
	c.Tag = c.buildNodeTag()

	// Log a clear mapping between Tag and NodeID for this controller instance.
	// This helps diagnose any cross-node mixing issues in multi-node deployments.
	c.logger.Infof("Controller mapping established: PanelHost=%s ApiClientNodeID=%d NodeInfoNodeID=%d NodeType=%s ListenIP=%s Port=%d Tag=%s",
		c.clientInfo.APIHost,
		c.clientInfo.NodeID,
		c.nodeInfo.NodeID,
		c.nodeInfo.NodeType,
		c.config.ListenIP,
		c.nodeInfo.Port,
		c.Tag,
	)

	// Add new tag
	err = c.addNewTag(newNodeInfo)
	if err != nil {
		c.logger.Error(err)
		return err
	}
	// Update user
	userInfo, err := c.apiClient.GetUserList()
	if err != nil {
		return err
	}

	// sync controller userList
	c.userList = userInfo

	err = c.addNewUser(userInfo, newNodeInfo)
	if err != nil {
		return err
	}

	// Add Limiter
	if err := c.AddInboundLimiter(c.Tag, newNodeInfo.SpeedLimit, userInfo, c.config.GlobalDeviceLimitConfig); err != nil {
		c.logger.Print(err)
	}

	// Add Rule Manager
	if !c.config.DisableGetRule {
		if ruleList, err := c.apiClient.GetNodeRule(); err != nil {
			c.logger.Printf("Get rule list filed: %s", err)
		} else if len(*ruleList) > 0 {
			if err := c.UpdateRule(c.Tag, *ruleList); err != nil {
				c.logger.Print(err)
			}
		}
		// Update exempt users
		if exemptUsers, err := c.apiClient.GetExemptUsers(); err != nil {
			c.logger.Printf("Get exempt users failed: %s", err)
		} else {
			c.dispatcher.RuleManager.UpdateExemptUsers(exemptUsers)
		}
	}

	// Init AutoSpeedLimitConfig
	if c.config.AutoSpeedLimitConfig == nil {
		c.config.AutoSpeedLimitConfig = &AutoSpeedLimitConfig{0, 0, 0, 0}
	}
	if c.config.AutoSpeedLimitConfig.Limit > 0 {
		c.limitedUsers = make(map[api.UserInfo]LimitInfo)
		c.warnedUsers = make(map[api.UserInfo]int)
	}

	// Add periodic tasks
	c.tasks = append(c.tasks,
		periodicTask{
			tag: "node monitor",
			Periodic: &task.Periodic{
				Interval: time.Duration(c.config.UpdatePeriodic) * time.Second,
				Execute:  c.nodeInfoMonitor,
			}},
		periodicTask{
			tag: "user monitor",
			Periodic: &task.Periodic{
				Interval: time.Duration(c.config.UpdatePeriodic) * time.Second,
				Execute:  c.userInfoMonitor,
			}},
	)

	// Check cert service in need
	// 只根据面板下发的节点配置判断是否启用 REALITY；本地 Config 不再参与 REALITY 逻辑
	if c.nodeInfo.EnableTLS && !c.nodeInfo.EnableREALITY {
		c.tasks = append(c.tasks, periodicTask{
			tag: "cert monitor",
			Periodic: &task.Periodic{
				Interval: time.Duration(c.config.UpdatePeriodic) * time.Second * 60,
				Execute:  c.certMonitor,
			}})
	}

	// Initialize unlock check if enabled
	if err := c.initUnlockCheck(); err != nil {
		c.logger.Printf("Failed to initialize unlock check: %v", err)
	}

	// Start periodic tasks
	for i := range c.tasks {
		c.logger.Printf("Start %s periodic task", c.tasks[i].tag)
		go c.tasks[i].Start()
	}

	return nil
}

// Close implement the Close() function of the service interface
func (c *Controller) Close() error {
	for i := range c.tasks {
		if c.tasks[i].Periodic != nil {
			if err := c.tasks[i].Periodic.Close(); err != nil {
				c.logger.Panicf("%s periodic task close failed: %s", c.tasks[i].tag, err)
			}
		}
	}

	// Remove VLESS same-node routing rule if it was added
	if strings.HasPrefix(c.Tag, "VLESS_") && c.router != nil {
		ruleTag := "vless-same-node-" + c.Tag
		if err := c.router.RemoveRule(ruleTag); err != nil {
			c.logger.Warnf("Failed to remove VLESS same-node routing rule %s: %v", ruleTag, err)
		} else {
			c.logger.Infof("Removed VLESS same-node routing rule: %s", ruleTag)
		}
	}

	return nil
}

func (c *Controller) nodeInfoMonitor() (err error) {
	// delay to start
	if time.Since(c.startAt) < time.Duration(c.config.UpdatePeriodic)*time.Second {
		return nil
	}

	// First fetch Node Info
	var nodeInfoChanged = true
	newNodeInfo, err := c.apiClient.GetNodeInfo()
	if err != nil {
		if err.Error() == api.NodeNotModified {
			nodeInfoChanged = false
			newNodeInfo = c.nodeInfo
			// Reset failure counter on successful "not modified" response
			c.consecutiveFailures = 0
		} else {
			c.logger.Print(err)
			// Track consecutive API failures for recovery
			if api.IsAPIFailure(err) {
				c.consecutiveFailures++
				c.lastFailureTime = time.Now()
				c.logger.Warnf("API communication failure detected (%d/%d)", c.consecutiveFailures, api.MaxConsecutiveFailures)

				// Check if we should trigger auto-recovery
				if c.consecutiveFailures >= api.MaxConsecutiveFailures {
					c.logger.Errorf("Consecutive API failures reached threshold (%d), triggering service recovery...", c.consecutiveFailures)
					c.triggerRecovery()
				}
			}
			return nil
		}
	}
	if c.consecutiveFailures != 0 {
		c.consecutiveFailures = 0
	}
	if newNodeInfo.Port == 0 {
		return errors.New("server port must > 0")
	}

	// Update User
	var usersChanged = true
	newUserInfo, err := c.apiClient.GetUserList()
	if err != nil {
		if err.Error() == api.UserNotModified {
			usersChanged = false
			newUserInfo = c.userList
			// Reset failure counter on successful "not modified" response
			c.consecutiveFailures = 0
		} else {
			c.logger.Print(err)
			if api.IsAPIFailure(err) {
				c.consecutiveFailures++
				c.lastFailureTime = time.Now()
				c.logger.Warnf("API communication failure detected (%d/%d)", c.consecutiveFailures, api.MaxConsecutiveFailures)
				if c.consecutiveFailures >= api.MaxConsecutiveFailures {
					c.logger.Errorf("Consecutive API failures reached threshold (%d), triggering service recovery...", c.consecutiveFailures)
					c.triggerRecovery()
				}
			}
			return nil
		}
	}
	if c.consecutiveFailures != 0 {
		c.consecutiveFailures = 0
	}

	// If nodeInfo changed
	if nodeInfoChanged {
		if !reflect.DeepEqual(c.nodeInfo, newNodeInfo) {
			// Remove old tag
			oldTag := c.Tag
			err := c.removeOldTag(oldTag)
			if err != nil {
				c.logger.Print(err)
				return nil
			}
			if c.nodeInfo.NodeType == "Shadowsocks-Plugin" {
				err = c.removeOldTag(fmt.Sprintf("dokodemo-door_%s+1", c.Tag))
			}
			if err != nil {
				c.logger.Print(err)
				return nil
			}
			// Add new tag
			c.nodeInfo = newNodeInfo
			c.Tag = c.buildNodeTag()
			c.logger.Infof("Node info changed, rebuild tag: oldTag=%s newTag=%s NodeID=%d NodeType=%s ListenIP=%s Port=%d",
				oldTag,
				c.Tag,
				c.nodeInfo.NodeID,
				c.nodeInfo.NodeType,
				c.config.ListenIP,
				c.nodeInfo.Port,
			)
			err = c.addNewTag(newNodeInfo)
			if err != nil {
				c.logger.Print(err)
				return nil
			}
			nodeInfoChanged = true
			// Remove Old limiter
			if err = c.DeleteInboundLimiter(oldTag); err != nil {
				c.logger.Print(err)
				return nil
			}
		} else {
			nodeInfoChanged = false
		}
	}

	// Check Rule
	if !c.config.DisableGetRule {
		if ruleList, err := c.apiClient.GetNodeRule(); err != nil {
			if err.Error() != api.RuleNotModified {
				c.logger.Printf("Get rule list filed: %s", err)
			}
		} else if len(*ruleList) > 0 {
			if err := c.UpdateRule(c.Tag, *ruleList); err != nil {
				c.logger.Print(err)
			}
		}
		// Update exempt users
		if exemptUsers, err := c.apiClient.GetExemptUsers(); err != nil {
			c.logger.Printf("Get exempt users failed: %s", err)
		} else {
			c.dispatcher.RuleManager.UpdateExemptUsers(exemptUsers)
		}
	}

	if nodeInfoChanged {
		err = c.addNewUser(newUserInfo, newNodeInfo)
		if err != nil {
			c.logger.Print(err)
			return nil
		}

		// Add Limiter
		if err := c.AddInboundLimiter(c.Tag, newNodeInfo.SpeedLimit, newUserInfo, c.config.GlobalDeviceLimitConfig); err != nil {
			c.logger.Print(err)
			return nil
		}

	} else {
		var deleted, added []api.UserInfo
		if usersChanged {
			deleted, added = compareUserList(c.userList, newUserInfo)
			if len(deleted) > 0 {
				deletedEmail := make([]string, len(deleted))
				for i, u := range deleted {
					deletedEmail[i] = c.buildUserTag(&u)
				}
				err := c.removeUsers(deletedEmail, c.Tag)
				if err != nil {
					c.logger.Print(err)
				}
			}
			if len(added) > 0 {
				err = c.addNewUser(&added, c.nodeInfo)
				if err != nil {
					c.logger.Print(err)
				}
				// Update Limiter
				if err := c.UpdateInboundLimiter(c.Tag, &added); err != nil {
					c.logger.Print(err)
				}
			}
		}
		c.logger.Printf("%d user deleted, %d user added", len(deleted), len(added))
	}
	c.userList = newUserInfo
	return nil
}

// triggerRecovery attempts to recover from consecutive API communication failures
// (e.g., IP whitelist issues) by stopping and restarting all periodic tasks.
// This allows the service to re-establish fresh connections when the panel
// eventually updates the whitelist.
func (c *Controller) triggerRecovery() {
	c.recoveryMutex.Lock()
	if c.recoveryInProgress {
		c.recoveryMutex.Unlock()
		c.logger.Warn("Recovery already in progress, skip duplicate trigger")
		return
	}
	c.recoveryInProgress = true
	c.recoveryMutex.Unlock()

	c.logger.Warn("Starting recovery procedure...")

	// Stop all periodic tasks
	for i := range c.tasks {
		if c.tasks[i].Periodic != nil {
			if err := c.tasks[i].Periodic.Close(); err != nil {
				c.logger.Errorf("Failed to stop %s task: %v", c.tasks[i].tag, err)
			}
		}
	}

	// Reset failure counter
	c.consecutiveFailures = 0

	// Restart periodic tasks after a short delay
	go func() {
		time.Sleep(5 * time.Second)
		c.logger.Info("Restarting periodic tasks...")
		for i := range c.tasks {
			c.logger.Printf("Restarting %s task", c.tasks[i].tag)
			go c.tasks[i].Start()
		}
		c.recoveryMutex.Lock()
		c.recoveryInProgress = false
		c.recoveryMutex.Unlock()
	}()
}

func (c *Controller) removeOldTag(oldTag string) (err error) {
	err = c.removeInbound(oldTag)
	if err != nil {
		return err
	}
	err = c.removeOutbound(oldTag)
	if err != nil {
		return err
	}
	return nil
}

func (c *Controller) addNewTag(newNodeInfo *api.NodeInfo) (err error) {
	if newNodeInfo.NodeType != "Shadowsocks-Plugin" {
		inboundConfig, err := InboundBuilder(c.config, newNodeInfo, c.Tag)
		if err != nil {
			return err
		}
		err = c.addInbound(inboundConfig)
		if err != nil {

			return err
		}
		outBoundConfig, err := OutboundBuilder(c.config, newNodeInfo, c.Tag)
		if err != nil {

			return err
		}
		err = c.addOutbound(outBoundConfig)
		if err != nil {

			return err
		}

		// For all ECYCloudNode-managed nodes, add a routing rule to enforce same-node routing.
		// This ensures the official dispatcher routes traffic directly to the corresponding
		// outbound without needing post-dispatch correction.
		// Supported protocols: VLESS, Trojan, Vmess, Shadowsocks
		if isECYCloudNodeManagedTag(c.Tag) && c.router != nil {
			routingRule := &router.RoutingRule{
				InboundTag: []string{c.Tag},
				TargetTag:  &router.RoutingRule_Tag{Tag: c.Tag},
				RuleTag:    "ecycloudnode-same-node-" + c.Tag,
			}
			// AddRule expects *router.Config, not *router.RoutingRule
			routerConfig := &router.Config{
				Rule: []*router.RoutingRule{routingRule},
			}
			ruleMsg := serial.ToTypedMessage(routerConfig)
			// Prepend the rule (shouldAppend=false) so it takes priority
			if err := c.router.AddRule(ruleMsg, false); err != nil {
				c.logger.Warnf("Failed to add ECYCloudNode same-node routing rule for %s: %v", c.Tag, err)
			} else {
				c.logger.Infof("Added ECYCloudNode same-node routing rule: inboundTag=%s -> outboundTag=%s", c.Tag, c.Tag)
			}
		}

	} else {
		return c.addInboundForSSPlugin(*newNodeInfo)
	}
	return nil
}

func (c *Controller) addInboundForSSPlugin(newNodeInfo api.NodeInfo) (err error) {
	// Shadowsocks-Plugin require a separate inbound for other TransportProtocol likes: ws, grpc
	fakeNodeInfo := newNodeInfo
	fakeNodeInfo.TransportProtocol = "tcp"
	fakeNodeInfo.EnableTLS = false
	// Add a regular Shadowsocks inbound and outbound
	inboundConfig, err := InboundBuilder(c.config, &fakeNodeInfo, c.Tag)
	if err != nil {
		return err
	}
	err = c.addInbound(inboundConfig)
	if err != nil {

		return err
	}
	outBoundConfig, err := OutboundBuilder(c.config, &fakeNodeInfo, c.Tag)
	if err != nil {

		return err
	}
	err = c.addOutbound(outBoundConfig)
	if err != nil {

		return err
	}
	// Add an inbound for upper streaming protocol
	fakeNodeInfo = newNodeInfo
	fakeNodeInfo.Port++
	fakeNodeInfo.NodeType = "dokodemo-door"
	dokodemoTag := fmt.Sprintf("dokodemo-door_%s+1", c.Tag)
	inboundConfig, err = InboundBuilder(c.config, &fakeNodeInfo, dokodemoTag)
	if err != nil {
		return err
	}
	err = c.addInbound(inboundConfig)
	if err != nil {

		return err
	}
	outBoundConfig, err = OutboundBuilder(c.config, &fakeNodeInfo, dokodemoTag)
	if err != nil {

		return err
	}
	err = c.addOutbound(outBoundConfig)
	if err != nil {

		return err
	}
	return nil
}

func (c *Controller) addNewUser(userInfo *[]api.UserInfo, nodeInfo *api.NodeInfo) (err error) {
	users := make([]*protocol.User, 0)
	switch nodeInfo.NodeType {
	case "Vmess", "VLESS":
		// VLESS / VMess users
		// chosen by NodeType
		if nodeInfo.NodeType == "VLESS" {
			users = c.buildVlessUser(userInfo)
		} else {
			users = c.buildVmessUser(userInfo)
		}
	case "Trojan":
		users = c.buildTrojanUser(userInfo)
	case "Shadowsocks":
		users = c.buildSSUser(userInfo, nodeInfo.CypherMethod)
	case "Shadowsocks-Plugin":
		users = c.buildSSPluginUser(userInfo)
	default:
		return fmt.Errorf("unsupported node type: %s", nodeInfo.NodeType)
	}

	err = c.addUsers(users, c.Tag)
	if err != nil {
		return err
	}
	c.logger.Printf("Added %d new users", len(*userInfo))
	return nil
}

func compareUserList(old, new *[]api.UserInfo) (deleted, added []api.UserInfo) {
	mSrc := make(map[api.UserInfo]byte) // 按源数组建索引
	mAll := make(map[api.UserInfo]byte) // 源+目所有元素建索引

	var set []api.UserInfo // 交集

	// 1.源数组建立map
	for _, v := range *old {
		mSrc[v] = 0
		mAll[v] = 0
	}
	// 2.目数组中，存不进去，即重复元素，所有存不进去的集合就是并集
	for _, v := range *new {
		l := len(mAll)
		mAll[v] = 1
		if l != len(mAll) { // 长度变化，即可以存
			l = len(mAll)
		} else { // 存不了，进并集
			set = append(set, v)
		}
	}
	// 3.遍历交集，在并集中找，找到就从并集中删，删完后就是补集（即并-交=所有变化的元素）
	for _, v := range set {
		delete(mAll, v)
	}
	// 4.此时，mall是补集，所有元素去源中找，找到就是删除的，找不到的必定能在目数组中找到，即新加的
	for v := range mAll {
		_, exist := mSrc[v]
		if exist {
			deleted = append(deleted, v)
		} else {
			added = append(added, v)
		}
	}

	return deleted, added
}

func limitUser(c *Controller, user api.UserInfo, silentUsers *[]api.UserInfo) {
	c.limitedUsers[user] = LimitInfo{
		end:               time.Now().Unix() + int64(c.config.AutoSpeedLimitConfig.LimitDuration*60),
		currentSpeedLimit: c.config.AutoSpeedLimitConfig.LimitSpeed,
		originSpeedLimit:  user.SpeedLimit,
	}
	c.logger.Printf("Limit User: %s Speed: %d End: %s", c.buildUserTag(&user), c.config.AutoSpeedLimitConfig.LimitSpeed, time.Unix(c.limitedUsers[user].end, 0).Format("01-02 15:04:05"))
	user.SpeedLimit = uint64((c.config.AutoSpeedLimitConfig.LimitSpeed * 1000000) / 8)
	*silentUsers = append(*silentUsers, user)
}

func (c *Controller) userInfoMonitor() (err error) {
	// delay to start
	if time.Since(c.startAt) < time.Duration(c.config.UpdatePeriodic)*time.Second {
		return nil
	}

	// Get server status
	CPU, Mem, Disk, Uptime, err := serverstatus.GetSystemInfo()
	if err != nil {
		c.logger.Print(err)
	}
	err = c.apiClient.ReportNodeStatus(
		&api.NodeStatus{
			CPU:    CPU,
			Mem:    Mem,
			Disk:   Disk,
			Uptime: Uptime,
		})
	if err != nil {
		c.logger.Print(err)
	}
	// Unlock users
	if c.config.AutoSpeedLimitConfig.Limit > 0 && len(c.limitedUsers) > 0 {
		c.logger.Printf("Limited users:")
		toReleaseUsers := make([]api.UserInfo, 0)
		for user, limitInfo := range c.limitedUsers {
			if time.Now().Unix() > limitInfo.end {
				user.SpeedLimit = limitInfo.originSpeedLimit
				toReleaseUsers = append(toReleaseUsers, user)
				c.logger.Printf("User: %s Speed: %d End: nil (Unlimit)", c.buildUserTag(&user), user.SpeedLimit)
				delete(c.limitedUsers, user)
			} else {
				c.logger.Printf("User: %s Speed: %d End: %s", c.buildUserTag(&user), limitInfo.currentSpeedLimit, time.Unix(c.limitedUsers[user].end, 0).Format("01-02 15:04:05"))
			}
		}
		if len(toReleaseUsers) > 0 {
			if err := c.UpdateInboundLimiter(c.Tag, &toReleaseUsers); err != nil {
				c.logger.Print(err)
			}
		}
	}

	// Get User traffic
	var userTraffic []api.UserTraffic
	var upCounterList []stats.Counter
	var downCounterList []stats.Counter
	AutoSpeedLimit := int64(c.config.AutoSpeedLimitConfig.Limit)
	UpdatePeriodic := int64(c.config.UpdatePeriodic)
	limitedUsers := make([]api.UserInfo, 0)
	for _, user := range *c.userList {
		userTag := c.buildUserTag(&user)
		up, down, upCounter, downCounter := c.getTraffic(userTag)
		if down > 0 {
			c.logger.Printf("Traffic counted: tag=%s up=%d down=%d", userTag, up, down)
		}
		if up > 0 || down > 0 {
			// Over speed users
			if AutoSpeedLimit > 0 {
				if down > AutoSpeedLimit*1000000*UpdatePeriodic/8 || up > AutoSpeedLimit*1000000*UpdatePeriodic/8 {
					if _, ok := c.limitedUsers[user]; !ok {
						if c.config.AutoSpeedLimitConfig.WarnTimes == 0 {
							limitUser(c, user, &limitedUsers)
						} else {
							c.warnedUsers[user] += 1
							if c.warnedUsers[user] > c.config.AutoSpeedLimitConfig.WarnTimes {
								limitUser(c, user, &limitedUsers)
								delete(c.warnedUsers, user)
							}
						}
					}
				} else {
					delete(c.warnedUsers, user)
				}
			}
			userTraffic = append(userTraffic, api.UserTraffic{
				UID:      user.UID,
				Email:    user.Email,
				Upload:   up,
				Download: down})

			if upCounter != nil {
				upCounterList = append(upCounterList, upCounter)
			}
			if downCounter != nil {
				downCounterList = append(downCounterList, downCounter)
			}
		} else {
			delete(c.warnedUsers, user)
		}
	}
	if len(limitedUsers) > 0 {
		if err := c.UpdateInboundLimiter(c.Tag, &limitedUsers); err != nil {
			c.logger.Print(err)
		}
	}
	if len(userTraffic) > 0 {
		c.logger.Printf("Reporting %d user(s) traffic to panel; example: UID=%d up=%d down=%d", len(userTraffic), userTraffic[0].UID, userTraffic[0].Upload, userTraffic[0].Download)
		var err error // Define an empty error
		if !c.config.DisableUploadTraffic {
			err = c.apiClient.ReportUserTraffic(&userTraffic)
		}
		// If report traffic error, not clear the traffic
		if err != nil {
			c.logger.Print(err)
		} else {
			c.resetTraffic(&upCounterList, &downCounterList)
		}
	}

	// Report Online info（空列表也上报，供面板按节点全量同步并清零 LastReportOnline）
	if onlineDevice, err := c.GetOnlineDevice(c.Tag); err != nil {
		c.logger.Print(err)
	} else {
		if err = c.apiClient.ReportNodeOnlineUsers(onlineDevice); err != nil {
			c.logger.Print(err)
		} else if len(*onlineDevice) > 0 {
			sample := (*onlineDevice)[0]
			c.logger.Printf(
				"Report %d online users (NodeID=%d, Tag=%s); example: UID=%d IP=%s",
				len(*onlineDevice),
				c.nodeInfo.NodeID,
				c.Tag,
				sample.UID,
				sample.IP,
			)
		}
		if kicks := limiter.TakeDeviceKicks(); len(kicks) > 0 {
			if err = c.apiClient.ReportKickedUsers(&kicks); err != nil {
				c.logger.Print(err)
			}
		}
	}

	// Report Illegal user
	if detectResult, err := c.GetDetectResult(c.Tag); err != nil {
		c.logger.Print(err)
	} else if len(*detectResult) > 0 {
		if err = c.apiClient.ReportIllegal(detectResult); err != nil {
			c.logger.Print(err)
		} else {
			sample := (*detectResult)[0]
			c.logger.Printf(
				"Report %d illegal behaviors (NodeID=%d, Tag=%s); example: UID=%d RuleID=%d IP=%s",
				len(*detectResult),
				c.nodeInfo.NodeID,
				c.Tag,
				sample.UID,
				sample.RuleID,
				sample.IP,
			)
		}

	}
	return nil
}

func (c *Controller) buildNodeTag() string {
	// Use a node-unique tag for all limiter/rule bookkeeping to avoid
	// cross-node mixing when multiple logical nodes share the same
	// NodeType + ListenIP + Port (e.g. multi-node, CDN, or offset-port
	// deployments). Including NodeID here guarantees that each SSPanel
	// node reports its own online users and audit results independently.
	return fmt.Sprintf("%s_%s_%d_%d", c.nodeInfo.NodeType, c.config.ListenIP, c.nodeInfo.Port, c.nodeInfo.NodeID)
}

// func (c *Controller) logPrefix() string {
// 	return fmt.Sprintf("[%s] %s(ID=%d)", c.clientInfo.APIHost, c.nodeInfo.NodeType, c.nodeInfo.NodeID)
// }

// Check Cert
func (c *Controller) certMonitor() error {
	// 仅当当前节点启用 TLS 且未启用 REALITY 时才进行证书监控。
	// 对于未设置 CertConfig 的旧配置，直接跳过证书监控以避免空指针。
	if c.config == nil || c.config.CertConfig == nil {
		return nil
	}
	if c.nodeInfo.EnableTLS && !c.nodeInfo.EnableREALITY {
		switch c.config.CertConfig.CertMode {
		case "dns", "http", "tls":
			lego, err := mylego.New(c.config.CertConfig)
			if err != nil {
				c.logger.Print(err)
			}
			// Xray-core supports the OcspStapling certification hot renew
			_, _, _, err = lego.RenewCert()
			if err != nil {
				c.logger.Print(err)
			}
		}
	}
	return nil
}

// initUnlockCheck initializes the unlock check periodic task.
// The actual configuration is fetched dynamically before each check (hot reload).
// Note: Node IDs are pre-registered in panel.Start() before any controller starts.
func (c *Controller) initUnlockCheck() error {
	c.unlockChecker = unlockcheck.NewChecker(c.logger)
	// Initialize lastUnlockCheckTime to zero so first check runs immediately after startup
	c.lastUnlockCheckTime = time.Time{}

	// Add unlock check periodic task with a base interval of 1 minute
	// The actual check execution is controlled by unlockCheckMonitor based on panel config
	c.tasks = append(c.tasks, periodicTask{
		tag: "unlock check",
		Periodic: &task.Periodic{
			Interval: 1 * time.Minute,
			Execute:  c.unlockCheckMonitor,
		}})

	c.logger.Printf("Unlock check task initialized for node %d (config will be fetched from panel)", c.nodeInfo.NodeID)

	return nil
}

// unlockCheckMonitor performs the streaming unlock check and reports results.
// It fetches the latest configuration from panel before each check (hot reload).
// Uses a node registry system: the first node to execute detection reports for ALL registered nodes.
// This eliminates the dependency on cache timing between nodes.
// Checks are executed at whole hours (00:00, 01:00, etc.) based on the configured interval.
func (c *Controller) unlockCheckMonitor() error {
	if c.unlockChecker == nil {
		return nil
	}

	// Use mutex to prevent concurrent execution within this node
	c.unlockCheckMutex.Lock()
	defer c.unlockCheckMutex.Unlock()

	nodeID := c.nodeInfo.NodeID

	// Check if this node has already been reported in this hour (by any node)
	if unlockcheck.HasNodeReported(nodeID) {
		return nil
	}

	// Fetch latest config from panel (hot reload)
	config, err := c.apiClient.GetUnlockCheckConfig()
	if err != nil {
		c.logger.Printf("[UnlockCheck] Node %d: Failed to get unlock check config: %v", nodeID, err)
		return nil
	}

	// Check if unlock check is enabled
	if !config.Enabled {
		return nil
	}

	// Check if interval is valid (interval is now in hours)
	if config.CheckInterval <= 0 {
		return nil
	}

	now := time.Now()
	currentHour := now.Hour()

	// Check if current hour matches the interval pattern
	if currentHour%config.CheckInterval != 0 {
		return nil
	}

	// Try to acquire the check lock (only one node should perform the actual check)
	if !unlockcheck.TryAcquireCheckLock() {
		// Another node is performing the check, skip this node
		// The node that acquired the lock will report for all nodes
		c.logger.Printf("[UnlockCheck] Node %d: Another node is performing check, skipping", nodeID)
		return nil
	}

	// This node acquired the lock, perform the check and report for ALL registered nodes
	defer unlockcheck.ReleaseCheckLock()

	c.logger.Printf("[UnlockCheck] Node %d: Performing check at %02d:%02d (interval: %d hours)", nodeID, currentHour, now.Minute(), config.CheckInterval)

	// Run all checks (will use csm.sh script)
	results := c.unlockChecker.RunAllChecks()

	// Store results in global cache
	unlockcheck.SetCachedResults(results)

	// Convert results to JSON
	resultJSON := results.ToJSON()
	c.logger.Printf("[UnlockCheck] Node %d: Results: %s", nodeID, resultJSON)

	// Get all registered node IDs and report for each one
	allNodeIDs := unlockcheck.GetRegisteredNodeIDs()
	c.logger.Printf("[UnlockCheck] Node %d: Reporting results for %d nodes: %v", nodeID, len(allNodeIDs), allNodeIDs)

	for _, targetNodeID := range allNodeIDs {
		if err := c.apiClient.ReportUnlockCheckResultForNode(targetNodeID, resultJSON); err != nil {
			c.logger.Printf("[UnlockCheck] Node %d: Failed to report for node %d: %v", nodeID, targetNodeID, err)
		} else {
			c.logger.Printf("[UnlockCheck] Node %d: Reported successfully for node %d", nodeID, targetNodeID)
			unlockcheck.MarkNodeReported(targetNodeID)
		}
	}

	// Update last report time for this node
	c.lastUnlockCheckTime = now

	return nil
}
