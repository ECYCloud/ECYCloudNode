package sspanel

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/go-resty/resty/v2"

	"github.com/ECYCloud/ECYCloudNode/api"
)

// APIClient create a api client to the panel.
type APIClient struct {
	client           *resty.Client
	trafficClient    *resty.Client // 流量上报专用，禁用重试避免超时重试导致流量重复提交
	APIHost          string
	NodeID           int
	Key              string
	SpeedLimit       float64
	DeviceLimit      int
	LocalRuleList    []api.DetectRule
	LastReportOnline map[int]int
	access           sync.Mutex
	// eTags 被节点与用户两个周期任务的 goroutine 共用，必须全程持锁访问：
	// 裸 map 的并发读写是 Go 运行时 fatal error，recover 拦不住。
	eTagsMu sync.Mutex
	eTags   map[string]string
	// exemptUsers caches the latest exempt user list from the panel
	exemptUsers []api.ExemptUser
}

func (c *APIClient) eTag(key string) string {
	c.eTagsMu.Lock()
	defer c.eTagsMu.Unlock()
	return c.eTags[key]
}

func (c *APIClient) setETag(key, value string) {
	c.eTagsMu.Lock()
	defer c.eTagsMu.Unlock()
	c.eTags[key] = value
}

// mapSortToNodeType
//
//	0/1 -> Shadowsocks
//	2   -> VLESS
//	11  -> Vmess
//	14  -> Trojan
//	15  -> Hysteria2
//	16  -> AnyTLS
//	17  -> Tuic
func mapSortToNodeType(sort int) string {
	switch sort {
	case 0, 1:
		return "Shadowsocks"
	case 2:
		return "VLESS"
	case 11:
		return "Vmess"
	case 14:
		return "Trojan"
	case 15:
		return "Hysteria2"
	case 16:
		return "AnyTLS"
	case 17:
		return "Tuic"
	default:
		return ""
	}
}

// New create api instance
func New(apiConfig *api.Config) *APIClient {
	client := resty.New()

	client.SetRetryCount(3)
	if apiConfig.Timeout > 0 {
		client.SetTimeout(time.Duration(apiConfig.Timeout) * time.Second)
	} else {
		client.SetTimeout(5 * time.Second)
	}
	client.OnError(func(req *resty.Request, err error) {
		var v *resty.ResponseError
		if errors.As(err, &v) {
			// v.Response contains the last response from the server
			// v.Err contains the original error
			log.Print(v.Err)
		}
	})

	client.SetBaseURL(apiConfig.APIHost)
	// Create Key for each requests
	client.SetQueryParam("key", apiConfig.Key)
	// Add support for muKey
	client.SetQueryParam("muKey", apiConfig.Key)

	// 流量上报专用客户端：禁用重试，避免超时重试导致流量重复提交
	trafficClient := resty.New()
	trafficClient.SetRetryCount(0)
	trafficClient.SetTimeout(30 * time.Second)
	trafficClient.OnError(func(req *resty.Request, err error) {
		var v *resty.ResponseError
		if errors.As(err, &v) {
			log.Print(v.Err)
		}
	})
	trafficClient.SetBaseURL(apiConfig.APIHost)
	trafficClient.SetQueryParam("key", apiConfig.Key)
	trafficClient.SetQueryParam("muKey", apiConfig.Key)

	// Read local rule list
	localRuleList := readLocalRuleList(apiConfig.RuleListPath)

	// Parse NodeID from configuration. Panel.expandNodesConfig has already
	// expanded any multi-node expression into separate logical nodes, so each
	// ApiConfig here should contain at most one logical NodeID.
	nodeIDStr := strings.TrimSpace(apiConfig.NodeID)
	nodeID := 0
	if nodeIDStr != "" {
		if id, err := strconv.Atoi(nodeIDStr); err == nil {
			nodeID = id
		} else {
			log.Warnf("invalid NodeID %q in ApiConfig, fallback to 0", apiConfig.NodeID)
		}
	}

	return &APIClient{
		client:           client,
		trafficClient:    trafficClient,
		NodeID:           nodeID,
		Key:              apiConfig.Key,
		APIHost:          apiConfig.APIHost,
		SpeedLimit:       apiConfig.SpeedLimit,
		DeviceLimit:      apiConfig.DeviceLimit,
		LocalRuleList:    localRuleList,
		LastReportOnline: make(map[int]int),
		eTags:            make(map[string]string),
	}
}

// readLocalRuleList reads the local rule list file
func readLocalRuleList(path string) (LocalRuleList []api.DetectRule) {
	LocalRuleList = make([]api.DetectRule, 0)
	if path != "" {
		// open the file
		file, err := os.Open(path)

		defer func(file *os.File) {
			err := file.Close()
			if err != nil {
				log.Printf("Error when closing file: %s", err)
			}
		}(file)
		// handle errors while opening
		if err != nil {
			log.Printf("Error when opening file: %s", err)
			return LocalRuleList
		}

		fileScanner := bufio.NewScanner(file)

		// read line by line
		for fileScanner.Scan() {
			// 空行编译出的正则匹配一切，会让该规则拒绝全部流量
			line := strings.TrimSpace(fileScanner.Text())
			if line == "" {
				continue
			}
			pattern, err := regexp.Compile(line)
			if err != nil {
				log.Printf("Invalid local rule pattern %q, skipped: %s", line, err)
				continue
			}
			LocalRuleList = append(LocalRuleList, api.DetectRule{
				ID:      -1,
				Pattern: pattern,
			})
		}
		// handle first encountered error while reading
		if err := fileScanner.Err(); err != nil {
			log.Fatalf("Error while reading file: %s", err)
			return
		}
	}

	return LocalRuleList
}

// Describe return a description of the client
func (c *APIClient) Describe() api.ClientInfo {
	return api.ClientInfo{APIHost: c.APIHost, NodeID: c.NodeID, Key: c.Key}
}

// Debug set the client debug for client
func (c *APIClient) Debug() {
	c.client.SetDebug(true)
}

func (c *APIClient) assembleURL(path string) string {
	return c.APIHost + path
}

func (c *APIClient) parseResponse(res *resty.Response, path string, err error) (*Response, error) {
	if err != nil {
		return nil, fmt.Errorf("request %s failed: %s", c.assembleURL(path), err)
	}

	if res.StatusCode() > 400 {
		body := res.Body()
		return nil, fmt.Errorf("request %s failed: %s, %v", c.assembleURL(path), string(body), err)
	}
	response := res.Result().(*Response)

	if response.Ret != 1 {
		res, _ := json.Marshal(&response)
		return nil, fmt.Errorf("ret %s invalid", string(res))
	}
	return response, nil
}

// GetNodeInfo will pull NodeInfo Config from ssPanel
func (c *APIClient) GetNodeInfo() (nodeInfo *api.NodeInfo, err error) {
	path := fmt.Sprintf("/mod_mu/nodes/%d/info", c.NodeID)
	res, err := c.client.R().
		SetResult(&Response{}).
		SetHeader("If-None-Match", c.eTag("node")).
		ForceContentType("application/json").
		Get(path)
	// Etag identifier for a specific version of a resource. StatusCode = 304 means no changed
	if res.StatusCode() == 304 {
		return nil, errors.New(api.NodeNotModified)
	}

	if eTag := res.Header().Get("ETag"); eTag != "" {
		c.setETag("node", eTag)
	}

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}

	nodeInfoResponse := new(NodeInfoResponse)

	if err := json.Unmarshal(response.Data, nodeInfoResponse); err != nil {
		return nil, fmt.Errorf("unmarshal %s failed: %s", reflect.TypeOf(nodeInfoResponse), err)
	}

	nodeInfo, err = c.ParseSSPanelNodeInfo(nodeInfoResponse)
	if err != nil {
		res, _ := json.Marshal(nodeInfoResponse)
		return nil, fmt.Errorf("parse node info failed: %s, \nError: %s", string(res), err)
	}

	return nodeInfo, nil
}

// GetECYCloudNodeCertConfig fetches optional global ECYCloudNode certificate
// configuration from the panel via /mod_mu/nodes/config with
// type = ecycloudnode_cert. This allows the panel to centrally control
// DNS provider, ACME email and DNS-01 environment variables
// (e.g. Cloudflare API credentials) for all nodes.
func (c *APIClient) GetECYCloudNodeCertConfig() (*api.ECYCloudNodeCertConfig, error) {
	return c.fetchCertConfigByType("ecycloudnode_cert")
}

func (c *APIClient) fetchCertConfigByType(configType string) (*api.ECYCloudNodeCertConfig, error) {
	path := "/mod_mu/nodes/config"
	payload := map[string]string{
		"type": configType,
	}

	res, err := c.client.R().
		SetBody(payload).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Post(path)

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}

	cfg := new(api.ECYCloudNodeCertConfig)
	if err := json.Unmarshal(response.Data, cfg); err != nil {
		return nil, fmt.Errorf("unmarshal %s failed: %s", reflect.TypeOf(cfg), err)
	}

	return cfg, nil
}

// GetGlobalLimitConfig fetches the panel-managed Redis connection info
// (site IP and Redis password, 设置中心-节点相关) via /mod_mu/nodes/config
// with type = global_limit, used by the cross-node global device limit.
func (c *APIClient) GetGlobalLimitConfig() (*api.GlobalLimitConfig, error) {
	path := "/mod_mu/nodes/config"
	payload := map[string]string{
		"type": "global_limit",
	}

	res, err := c.client.R().
		SetBody(payload).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Post(path)

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}

	cfg := new(api.GlobalLimitConfig)
	if err := json.Unmarshal(response.Data, cfg); err != nil {
		return nil, fmt.Errorf("unmarshal %s failed: %s", reflect.TypeOf(cfg), err)
	}

	return cfg, nil
}

// GetWebAPIConfig fetches the current panel API host (设置中心「订阅域名」)
// via /mod_mu/nodes/config with type = webapi.
func (c *APIClient) GetWebAPIConfig() (*api.WebAPIConfig, error) {
	path := "/mod_mu/nodes/config"
	payload := map[string]string{
		"type": "webapi",
	}

	res, err := c.client.R().
		SetBody(payload).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Post(path)

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}

	cfg := new(api.WebAPIConfig)
	if err := json.Unmarshal(response.Data, cfg); err != nil {
		return nil, fmt.Errorf("unmarshal %s failed: %s", reflect.TypeOf(cfg), err)
	}

	return cfg, nil
}

// GetUserList will pull user form ssPanel
func (c *APIClient) GetUserList() (UserList *[]api.UserInfo, err error) {
	path := "/mod_mu/users"
	res, err := c.client.R().
		SetQueryParam("node_id", strconv.Itoa(c.NodeID)).
		SetHeader("If-None-Match", c.eTag("users")).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Get(path)
	// Etag identifier for a specific version of a resource. StatusCode = 304 means no changed
	if res.StatusCode() == 304 {
		return nil, errors.New(api.UserNotModified)
	}

	if eTag := res.Header().Get("ETag"); eTag != "" {
		c.setETag("users", eTag)
	}

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}

	userListResponse := new([]UserResponse)

	if err := json.Unmarshal(response.Data, userListResponse); err != nil {
		return nil, fmt.Errorf("unmarshal %s failed: %s", reflect.TypeOf(userListResponse), err)
	}
	userList, err := c.ParseUserListResponse(userListResponse)
	if err != nil {
		res, _ := json.Marshal(userListResponse)
		return nil, fmt.Errorf("parse user list failed: %s", string(res))
	}
	return userList, nil
}

// ReportNodeStatus reports the node status to the ssPanel
func (c *APIClient) ReportNodeStatus(nodeStatus *api.NodeStatus) (err error) {
	// Always report node status for all panel versions
	path := fmt.Sprintf("/mod_mu/nodes/%d/info", c.NodeID)
	systemLoad := SystemLoad{
		Uptime: strconv.FormatUint(nodeStatus.Uptime, 10),
		Load:   fmt.Sprintf("%.2f %.2f %.2f", nodeStatus.CPU/100, nodeStatus.Mem/100, nodeStatus.Disk/100),
	}

	res, err := c.client.R().
		SetBody(systemLoad).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Post(path)

	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}

	return nil
}

// ReportNodeOnlineUsers reports online user ip
func (c *APIClient) ReportNodeOnlineUsers(onlineUserList *[]api.OnlineUser) error {
	c.access.Lock()
	defer c.access.Unlock()

	reportOnline := make(map[int]int)
	var data []OnlineUser
	if onlineUserList != nil {
		data = make([]OnlineUser, len(*onlineUserList))
		for i, user := range *onlineUserList {
			data[i] = OnlineUser{UID: user.UID, IP: user.IP}
			reportOnline[user.UID]++
		}
	}
	// 空列表也必须上报并重置 LastReportOnline，否则下线 IP 后本节点仍保留旧计数，
	// 面板 alive_ip 也无法按节点全量同步清除，导致名额长期被占。
	c.LastReportOnline = reportOnline

	if len(data) > 0 {
		first := data[0]
		log.Printf(
			"ReportNodeOnlineUsers: node_id=%d online_count=%d example: UID=%d IP=%s",
			c.NodeID,
			len(data),
			first.UID,
			first.IP,
		)
	} else {
		log.Printf("ReportNodeOnlineUsers: node_id=%d online_count=0 (sync purge)", c.NodeID)
	}

	postData := &PostData{Data: data}
	path := "/mod_mu/users/aliveip"
	res, err := c.client.R().
		SetQueryParam("node_id", strconv.Itoa(c.NodeID)).
		SetBody(postData).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Post(path)

	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}

	return nil
}

// ReportKickedUsers reports IPs kicked due to device limit exceeded.
func (c *APIClient) ReportKickedUsers(kickedUserList *[]api.OnlineUser) error {
	if kickedUserList == nil || len(*kickedUserList) == 0 {
		return nil
	}

	data := make([]OnlineUser, len(*kickedUserList))
	for i, user := range *kickedUserList {
		data[i] = OnlineUser{UID: user.UID, IP: user.IP}
	}
	postData := &PostData{Data: data}
	path := "/mod_mu/users/ipkick"
	res, err := c.client.R().
		SetQueryParam("node_id", strconv.Itoa(c.NodeID)).
		SetBody(postData).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Post(path)

	_, err = c.parseResponse(res, path, err)
	return err
}

func (c *APIClient) ConsumeIpReclaim(uid int, ip string) (bool, string, error) {
	if uid <= 0 || ip == "" {
		return false, "", nil
	}

	path := "/mod_mu/users/ipreclaim"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := c.trafficClient.R().
		SetContext(ctx).
		SetQueryParam("node_id", strconv.Itoa(c.NodeID)).
		SetBody(&PostData{Data: map[string]interface{}{"user_id": uid, "ip": ip}}).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Post(path)

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return false, "", err
	}

	var payload struct {
		OK       bool   `json:"ok"`
		TargetIP string `json:"target_ip"`
	}
	if err := json.Unmarshal(response.Data, &payload); err != nil {
		return false, "", fmt.Errorf("unmarshal ipreclaim failed: %s", err)
	}
	return payload.OK, payload.TargetIP, nil
}

// ReportUserTraffic reports the user traffic
func (c *APIClient) ReportUserTraffic(userTraffic *[]api.UserTraffic) error {

	data := make([]UserTraffic, len(*userTraffic))
	for i, traffic := range *userTraffic {
		data[i] = UserTraffic{
			UID:      traffic.UID,
			Upload:   traffic.Upload,
			Download: traffic.Download}
	}
	postData := &PostData{Data: data}
	path := "/mod_mu/users/traffic"
	res, err := c.trafficClient.R().
		SetQueryParam("node_id", strconv.Itoa(c.NodeID)).
		SetBody(postData).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Post(path)
	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}

	return nil
}

// GetNodeRule will pull the audit rule form ssPanel
func (c *APIClient) GetNodeRule() (*[]api.DetectRule, error) {
	ruleList := c.LocalRuleList
	path := "/mod_mu/func/detect_rules"
	res, err := c.client.R().
		SetHeader("If-None-Match", c.eTag("rules")).
		ForceContentType("application/json").
		Get(path)

	if err != nil {
		return nil, fmt.Errorf("request %s failed: %s", c.assembleURL(path), err)
	}

	// Etag identifier for a specific version of a resource. StatusCode = 304 means no changed
	if res.StatusCode() == 304 {
		return nil, errors.New(api.RuleNotModified)
	}

	if res.StatusCode() > 400 {
		return nil, fmt.Errorf("request %s failed with status: %d", c.assembleURL(path), res.StatusCode())
	}

	if eTag := res.Header().Get("ETag"); eTag != "" {
		c.setETag("rules", eTag)
	}

	// Parse the full response including exempt_users
	var ruleResp RuleListResponse
	if err := json.Unmarshal(res.Body(), &ruleResp); err != nil {
		return nil, fmt.Errorf("unmarshal rule response failed: %s", err)
	}

	if ruleResp.Ret != 1 {
		return nil, fmt.Errorf("GetNodeRule: ret=%d", ruleResp.Ret)
	}

	ruleListResponse := new([]RuleItem)
	if err := json.Unmarshal(ruleResp.Data, ruleListResponse); err != nil {
		return nil, fmt.Errorf("unmarshal %s failed: %s", reflect.TypeOf(ruleListResponse), err)
	}

	for _, r := range *ruleListResponse {
		// 规则内容由面板管理员填写，一条写坏不能连带整个节点崩溃
		pattern, err := regexp.Compile(r.Content)
		if err != nil {
			log.Printf("Invalid detect rule %d pattern %q, skipped: %s", r.ID, r.Content, err)
			continue
		}
		ruleList = append(ruleList, api.DetectRule{
			ID:      r.ID,
			Pattern: pattern,
		})
	}

	// Parse exempt users and cache them
	c.exemptUsers = parseExemptUsers(ruleResp.ExemptUsers)

	return &ruleList, nil
}

// parseExemptUsers converts the panel's exempt_users JSON to ExemptUser slice.
// Expected format (object value):
//
//	{"<uid>": {"rules": "*"|"id,id,...", "nodes": "*"|"nid,nid,..."}, ...}
//
// An empty JSON array [] (a PHP quirk for empty associative arrays) is treated
// as "no exempt users".
func parseExemptUsers(raw json.RawMessage) []api.ExemptUser {
	if len(raw) == 0 {
		return nil
	}
	type exemptItem struct {
		Rules string `json:"rules"`
		Nodes string `json:"nodes"`
	}
	var m map[string]exemptItem
	if err := json.Unmarshal(raw, &m); err != nil {
		// Likely an empty JSON array [] — not an error, just no exempt users
		return nil
	}
	if len(m) == 0 {
		return nil
	}
	splitIDs := func(s string) []int {
		var ids []int
		for _, p := range strings.Split(s, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if id, err := strconv.Atoi(p); err == nil {
				ids = append(ids, id)
			}
		}
		return ids
	}
	var result []api.ExemptUser
	for uidStr, item := range m {
		uid, err := strconv.Atoi(uidStr)
		if err != nil {
			continue
		}
		eu := api.ExemptUser{UID: uid}
		if item.Rules == "*" {
			eu.GlobalExempt = true
		} else {
			eu.ExemptRuleIDs = splitIDs(item.Rules)
		}
		if item.Nodes == "*" {
			eu.GlobalNode = true
		} else {
			eu.ExemptNodeIDs = splitIDs(item.Nodes)
		}
		result = append(result, eu)
	}
	return result
}

// GetExemptUsers returns the cached exempt user list from the last GetNodeRule call
func (c *APIClient) GetExemptUsers() ([]api.ExemptUser, error) {
	return c.exemptUsers, nil
}

// ReportIllegal reports the user illegal behaviors
func (c *APIClient) ReportIllegal(detectResultList *[]api.DetectResult) error {

	data := make([]IllegalItem, len(*detectResultList))
	for i, r := range *detectResultList {
		data[i] = IllegalItem{
			ID:  r.RuleID,
			UID: r.UID,
			IP:  r.IP,
		}
	}

	if len(data) > 0 {
		first := data[0]
		log.Printf(
			"ReportIllegal: node_id=%d count=%d example: UID=%d RuleID=%d IP=%s",
			c.NodeID,
			len(data),
			first.UID,
			first.ID,
			first.IP,
		)
	}
	postData := &PostData{Data: data}
	path := "/mod_mu/users/detectlog"
	res, err := c.client.R().
		SetQueryParam("node_id", strconv.Itoa(c.NodeID)).
		SetBody(postData).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Post(path)
	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}
	return nil
}

// ParseUserListResponse parse the response for the given node info format
func (c *APIClient) ParseUserListResponse(userInfoResponse *[]UserResponse) (*[]api.UserInfo, error) {
	// Lock while reading LastReportOnline snapshot; do NOT clear it here.
	c.access.Lock()
	defer c.access.Unlock()

	var deviceLimit, localDeviceLimit = 0, 0
	var speedLimit uint64 = 0
	var userList []api.UserInfo
	for _, user := range *userInfoResponse {
		if c.DeviceLimit > 0 {
			deviceLimit = c.DeviceLimit
		} else {
			deviceLimit = user.DeviceLimit
		}

		// 超限时由节点本地/Redis 踢最旧 IP，不再因全局已满而跳过下发用户。
		if deviceLimit > 0 && user.AliveIP > 0 {
			lastOnline := 0
			if v, ok := c.LastReportOnline[user.ID]; ok {
				lastOnline = v
			}
			if localDeviceLimit = deviceLimit - user.AliveIP + lastOnline; localDeviceLimit > 0 {
				deviceLimit = localDeviceLimit
			} else if lastOnline > 0 {
				deviceLimit = lastOnline
			}
		}

		if c.SpeedLimit > 0 {
			speedLimit = uint64((c.SpeedLimit * 1000000) / 8)
		} else {
			speedLimit = uint64((user.SpeedLimit * 1000000) / 8)
		}
		userList = append(userList, api.UserInfo{
			UID:         user.ID,
			UUID:        user.UUID,
			Passwd:      user.Passwd,
			SpeedLimit:  speedLimit,
			DeviceLimit: deviceLimit,
			Port:        user.Port,
			Method:      user.Method,
		})
	}

	return &userList, nil
}

// ParseSSPanelNodeInfo parse the response for the given node info format
// Only available for SSPanel version >= 2021.11
func (c *APIClient) ParseSSPanelNodeInfo(nodeInfoResponse *NodeInfoResponse) (*api.NodeInfo, error) {
	var (
		speedLimit        uint64 = 0
		enableTLS         bool
		transportProtocol string
	)

	// NodeTypesort
	effectiveNodeType := mapSortToNodeType(nodeInfoResponse.Sort)
	if effectiveNodeType == "" {
		return nil, fmt.Errorf("unsupported node sort: %d", nodeInfoResponse.Sort)
	}

	// Check if custom_config is null
	if len(nodeInfoResponse.CustomConfig) == 0 {
		return nil, errors.New("custom_config is empty, disable custom config")
	}

	nodeConfig := new(CustomConfig)
	err := json.Unmarshal(nodeInfoResponse.CustomConfig, nodeConfig)
	if err != nil {
		return nil, fmt.Errorf("custom_config format error: %v", err)
	}

	if c.SpeedLimit > 0 {
		speedLimit = uint64((c.SpeedLimit * 1000000) / 8)
	} else {
		speedLimit = uint64((nodeInfoResponse.SpeedLimit * 1000000) / 8)
	}

	parsedPort, err := strconv.ParseInt(nodeConfig.OffsetPortNode, 10, 32)
	if err != nil {
		return nil, err
	}

	port := uint32(parsedPort)

	switch effectiveNodeType {
	case "Shadowsocks":
		transportProtocol = "tcp"
	case "Vmess":
		transportProtocol = nodeConfig.Network

		tlsType := nodeConfig.Security
		if tlsType == "tls" || tlsType == "xtls" {
			enableTLS = true
		}
	case "VLESS":
		// VLESS 与 VMess 在传输层上的配置字段基本一致：
		// - network   -> TransportProtocol
		// - security  -> 是否启用 TLS（非 REALITY 场景）
		// 若 network 为空，则在后面统一回退到 "tcp"，避免出现
		// "unknown transport protocol: \"\"" 这类致命错误。
		transportProtocol = nodeConfig.Network

		tlsType := nodeConfig.Security
		if tlsType == "tls" || tlsType == "xtls" {
			enableTLS = true
		}
	case "Trojan":
		enableTLS = true
		transportProtocol = "tcp"

		// Select transport protocol
		if nodeConfig.Network != "" {
			transportProtocol = nodeConfig.Network // try to read transport protocol from config
		}
	case "Hysteria2":
		// Hysteria2 uses UDP transport and always requires TLS on the server side
		transportProtocol = "udp"
		enableTLS = true
	case "AnyTLS":
		// AnyTLS is a TLS-based protocol implemented by sing-box and uses TCP transport.
		transportProtocol = "tcp"
		enableTLS = true
	case "Tuic":
		// TUIC uses QUIC transport and always requires TLS
		transportProtocol = "udp"
		enableTLS = true
	}

	// 对于历史遗留节点，如果 custom_config 中未显式设置 network，
	// 这里为常见协议类型填充一个安全的默认值，避免因为空字符串导致
	// InboundBuilder 中的 TransportProtocol.Build() 直接 panic。
	if transportProtocol == "" {
		switch effectiveNodeType {
		case "Vmess", "VLESS", "Shadowsocks", "Trojan", "AnyTLS":
			transportProtocol = "tcp"
		case "Hysteria2", "Tuic":
			transportProtocol = "udp"
		}
	}

	// parse reality config
	realityConfig := new(api.REALITYConfig)
	if nodeConfig.RealityOpts != nil {
		r := nodeConfig.RealityOpts
		// ProxyProtocolVer 即 REALITY 的 Xver：回落/镜像连接 dest 时向 dest 发送 PROXY 头，
		// 仅适用于 dest 为自建且开启 proxy_protocol 的服务，只认 reality-opts.proxy_protocol_ver。
		// 注意不能回退到节点级 proxy_protocol_ver（那是入站接受 PROXY 头的开关配套字段），
		// 否则公网伪装站收到 PROXY 头会直接断开，REALITY 镜像不到 ServerHello，握手必然失败。
		realityConfig = &api.REALITYConfig{
			Dest:             r.Dest,
			ProxyProtocolVer: r.ProxyProtocolVer,
			ServerNames:      r.ServerNames,
			PrivateKey:       r.PrivateKey,
			MinClientVer:     r.MinClientVer,
			MaxClientVer:     r.MaxClientVer,
			MaxTimeDiff:      r.MaxTimeDiff,
			ShortIds:         r.ShortIds,
			Mldsa65Seed:      r.Mldsa65Seed,
		}
	}

	// 伪装头只有 tcp 与 mKCP 两种传输认，none 与不设置等价。
	// xray 的 tcp 伪装头只接受 http，其余取值（srtp / utp / wechat-video /
	// dtls / wireguard）属 mKCP，原样下发交由内核判定合法性。
	var header json.RawMessage
	switch {
	case transportProtocol == "tcp" && nodeConfig.HeaderType == "http",
		transportProtocol == "kcp" && nodeConfig.HeaderType != "" && nodeConfig.HeaderType != "none":
		header, err = json.Marshal(map[string]string{"type": nodeConfig.HeaderType})
		if err != nil {
			return nil, fmt.Errorf("marshal header type %s failed: %v", nodeConfig.HeaderType, err)
		}
	}

	// Derive SNI from custom_config. Prefer explicit SNI / server_name,
	// fall back to Host when those are empty.
	sni := ""
	if nodeConfig.Sni != "" {
		sni = nodeConfig.Sni
	} else if nodeConfig.ServerName != "" {
		sni = nodeConfig.ServerName
	} else {
		sni = nodeConfig.Host
	}

	// Create GeneralNodeInfo
	nodeInfo := &api.NodeInfo{
		NodeType:            effectiveNodeType,
		NodeID:              c.NodeID,
		Port:                port,
		SpeedLimit:          speedLimit,
		TransportProtocol:   transportProtocol,
		Host:                nodeConfig.Host,
		Path:                nodeConfig.Path,
		SNI:                 sni,
		EnableTLS:           enableTLS,
		VlessFlow:           nodeConfig.Flow,
		VlessDecryption:     nodeConfig.Decryption,
		CypherMethod:        nodeConfig.Method,
		ServerKey:           nodeConfig.ServerKey,
		ServiceName:         nodeConfig.Servicename,
		Header:              header,
		Seed:                nodeConfig.Seed,
		EnableREALITY:       nodeConfig.EnableREALITY,
		REALITYConfig:       realityConfig,
		AcceptProxyProtocol: nodeConfig.EnableProxyProtocol,
		ProxyProtocolVer:    nodeConfig.ProxyProtocolVer,
	}

	// Attach Hysteria2-specific configuration when needed
	if effectiveNodeType == "Hysteria2" {
		// up_mbps / down_mbps may be provided as strings in custom_config
		// 未配置或配置为非正数时，视为不限速（0 表示不在服务器侧强制带宽上限）
		up := 0
		if nodeConfig.UpMbps != "" {
			if v, err := strconv.Atoi(nodeConfig.UpMbps); err == nil && v > 0 {
				up = v
			}
		}
		down := 0
		if nodeConfig.DownMbps != "" {
			if v, err := strconv.Atoi(nodeConfig.DownMbps); err == nil && v > 0 {
				down = v
			}
		}

		// Hysteria2 端口跳跃配置：与面板侧的 getHysteria2PortHopConfig 语义保持一致。
		//
		// - port_hop_enable 支持 1/0、true/false、on/off、yes/no 等写法；
		// - port_hop_ports 支持字符串或字符串数组，内部统一规整为
		//   使用英文逗号分隔的表达式，例如 "30000-50000,60000"。
		portHopEnabled := parseBoolLooseJSON(nodeConfig.PortHopEnableRaw)
		portHopPorts := ""
		if portHopEnabled {
			portHopPorts = parsePortHopPortsExpr(nodeConfig.PortHopPortsRaw)
			if portHopPorts == "" {
				// 如果端口表达式为空，则视为未启用端口跳跃。
				portHopEnabled = false
			}
		}

		nodeInfo.Hysteria2Config = &api.Hysteria2Config{
			Obfs:                  nodeConfig.Obfs,
			ObfsPassword:          nodeConfig.ObfsPassword,
			UpMbps:                up,
			DownMbps:              down,
			IgnoreClientBandwidth: nodeConfig.IgnoreClientBandwidth,
			PortHopEnabled:        portHopEnabled,
			PortHopPorts:          portHopPorts,
		}
	}

	// Attach AnyTLS-specific configuration when needed
	if effectiveNodeType == "AnyTLS" {
		nodeInfo.AnyTLSConfig = &api.AnyTLSConfig{
			PaddingScheme: nodeConfig.PaddingScheme,
		}
	}

	// Attach TUIC-specific configuration when needed
	if effectiveNodeType == "Tuic" {
		// Parse heartbeat interval
		heartbeat := 10 // default 10 seconds
		if nodeConfig.Heartbeat != "" {
			if v, err := strconv.Atoi(nodeConfig.Heartbeat); err == nil && v > 0 {
				heartbeat = v
			}
		}

		// Parse zero_rtt_handshake from string "0"/"1" to bool
		zeroRTT := nodeConfig.ZeroRTTHandshake == "1" || nodeConfig.ZeroRTTHandshake == "true"

		nodeInfo.TuicConfig = &api.TuicConfig{
			CongestionControl: nodeConfig.CongestionControl,
			UDPRelayMode:      nodeConfig.UDPRelayMode,
			ZeroRTTHandshake:  zeroRTT,
			Heartbeat:         heartbeat,
			ALPN:              nodeConfig.Alpn,
		}
	}

	return nodeInfo, nil
}

// parseBoolLooseJSON 尝试将任意 JSON 标量（bool / number / string）解析为布尔值，
// 语义上尽量贴近 PHP 的 FILTER_VALIDATE_BOOLEAN（带 FILTER_NULL_ON_FAILURE）。
func parseBoolLooseJSON(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}

	// 直接解析为 bool
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		return b
	}

	// 尝试解析为数字
	var n int
	if err := json.Unmarshal(raw, &n); err == nil {
		return n != 0
	}

	// 尝试解析为字符串
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		s = strings.TrimSpace(strings.ToLower(s))
		switch s {
		case "", "0", "false", "off", "no", "n":
			return false
		case "1", "true", "on", "yes", "y":
			return true
		default:
			return false
		}
	}

	return false
}

// parsePortHopPortsExpr 将 custom_config 中的 port_hop_ports 规整为英文逗号分隔
// 的表达式，例如 "30000-50000,60000"，以方便在 Go 端进一步解析。
func parsePortHopPortsExpr(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}

	// 尝试解析为字符串数组
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		segments := make([]string, 0, len(list))
		for _, seg := range list {
			seg = strings.TrimSpace(seg)
			if seg == "" {
				continue
			}
			segments = append(segments, seg)
		}
		return strings.Join(segments, ",")
	}

	// 尝试解析为单个字符串
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		s = strings.TrimSpace(s)
		if s == "" {
			return ""
		}
		segments := splitPortsExprString(s)
		return strings.Join(segments, ",")
	}

	return ""
}

// splitPortsExprString 将可能包含空格 / 英文逗号 / 中文逗号的端口表达式切分为片段。
func splitPortsExprString(s string) []string {
	f := func(r rune) bool {
		return r == ',' || r == '，' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}
	parts := strings.FieldsFunc(s, f)
	segments := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		segments = append(segments, p)
	}
	return segments
}

// GetUnlockCheckConfig fetches the streaming unlock check configuration from the panel.
// This includes whether unlock check is enabled and the check interval in hours.
func (c *APIClient) GetUnlockCheckConfig() (*api.UnlockCheckConfig, error) {
	path := "/mod_mu/unlock/config"
	res, err := c.client.R().
		SetQueryParam("node_id", strconv.Itoa(c.NodeID)).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Get(path)

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}

	configResponse := new(UnlockCheckConfigResponse)
	if err := json.Unmarshal(response.Data, configResponse); err != nil {
		return nil, fmt.Errorf("unmarshal unlock check config failed: %s", err)
	}

	return &api.UnlockCheckConfig{
		Enabled:       configResponse.Enabled,
		CheckInterval: configResponse.CheckInterval,
	}, nil
}

// ReportUnlockCheckResult reports the streaming unlock check results to the panel.
// The result parameter should be a JSON string containing all check results.
func (c *APIClient) ReportUnlockCheckResult(result string) error {
	return c.ReportUnlockCheckResultForNode(c.NodeID, result)
}

// ReportUnlockCheckResultForNode reports the streaming unlock check results for a specific node.
// This allows one node to report results for multiple nodes (e.g., when using shared detection).
func (c *APIClient) ReportUnlockCheckResultForNode(nodeID int, result string) error {
	path := "/mod_mu/unlock/report"
	postData := &UnlockCheckResultPost{
		NodeID: nodeID,
		Result: result,
	}

	res, err := c.client.R().
		SetBody(postData).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Post(path)

	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}

	return nil
}
