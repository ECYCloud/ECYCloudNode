// Package rule is to control the audit rule behaviors
package rule

import (
	"context"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"

	mapset "github.com/deckarep/golang-set/v3"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/xtls/xray-core/common/errors"

	"github.com/ECYCloud/ECYCloudNode/api"
)

type Manager struct {
	InboundRule         *sync.Map // Key: Tag, Value: []api.DetectRule
	InboundDetectResult *sync.Map // key: Tag, Value: mapset.NewSet []api.DetectResult
	// exemptUsers 按节点 tag 分别存各自面板下发的豁免表。Key: Tag, Value: *sync.Map（UID -> *api.ExemptUser）
	// 同一 xray 进程的多面板节点共用一个 Manager，不同面板的同号 UID 是不同的用户。
	exemptUsers *sync.Map
}

func New() *Manager {
	return &Manager{
		InboundRule:         new(sync.Map),
		InboundDetectResult: new(sync.Map),
		exemptUsers:         new(sync.Map),
	}
}

// UpdateExemptUsers replaces the exempt user list of the node tag
// 先写入新表再删去不在其中的旧项：先清空再写入时，并发的审计会在窗口内误拦豁免用户。
func (r *Manager) UpdateExemptUsers(tag string, users []api.ExemptUser) {
	value, _ := r.exemptUsers.LoadOrStore(tag, new(sync.Map))
	table := value.(*sync.Map)
	current := make(map[int]bool, len(users))
	for i := range users {
		table.Store(users[i].UID, &users[i])
		current[users[i].UID] = true
	}
	table.Range(func(key, value interface{}) bool {
		if !current[key.(int)] {
			table.Delete(key)
		}
		return true
	})
}

// isExempt checks if a user (by UID) is exempt from a specific rule on a given node.
// nodeID < 0 means "node unknown" — in that case we still respect the rules-dimension
// exemption to avoid over-blocking, but cannot enforce node-scope precisely.
func (r *Manager) isExempt(tag string, uid int, ruleID int, nodeID int) bool {
	table, ok := r.exemptUsers.Load(tag)
	if !ok {
		return false
	}
	val, ok := table.(*sync.Map).Load(uid)
	if !ok {
		return false
	}
	eu := val.(*api.ExemptUser)
	// 1) Node-dimension gate: must match either "all nodes" or this nodeID
	if !eu.GlobalNode {
		if nodeID < 0 {
			return false
		}
		matched := false
		for _, nid := range eu.ExemptNodeIDs {
			if nid == nodeID {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	// 2) Rule-dimension gate
	if eu.GlobalExempt {
		return true
	}
	for _, rid := range eu.ExemptRuleIDs {
		if rid == ruleID {
			return true
		}
	}
	return false
}

// nodeIDFromTag extracts the trailing NodeID from a ECYCloudNode-managed tag.
// Tag format: {Protocol}_{IP}_{Port}_{NodeID}
// Returns -1 when the tag does not carry a parseable NodeID.
func nodeIDFromTag(tag string) int {
	idx := strings.LastIndex(tag, "_")
	if idx < 0 || idx == len(tag)-1 {
		return -1
	}
	if n, err := strconv.Atoi(tag[idx+1:]); err == nil {
		return n
	}
	return -1
}

func (r *Manager) UpdateRule(tag string, newRuleList []api.DetectRule) error {
	if value, ok := r.InboundRule.LoadOrStore(tag, newRuleList); ok {
		oldRuleList := value.([]api.DetectRule)
		if !reflect.DeepEqual(oldRuleList, newRuleList) {
			r.InboundRule.Store(tag, newRuleList)
		}
	}
	return nil
}

func (r *Manager) GetDetectResult(tag string) (*[]api.DetectResult, error) {
	detectResult := make([]api.DetectResult, 0)
	if value, ok := r.InboundDetectResult.LoadAndDelete(tag); ok {
		resultSet := value.(mapset.Set[api.DetectResult])
		it := resultSet.Iterator()
		for result := range it.C {
			detectResult = append(detectResult, result)
		}
	}
	return &detectResult, nil
}

func (r *Manager) Detect(tag string, destination string, userKey string, srcIP string) (reject bool) {
	reject = false
	destination = normalizeDestination(destination)
	var hitRuleID = -1
	// Parse UID early so we can check exemptions before rejecting
	uid := -1
	if n, err := strconv.Atoi(userKey); err == nil {
		uid = n
	} else {
		parts := strings.Split(userKey, "|")
		if n, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
			uid = n
		}
	}
	// Resolve current node ID from tag (format: {Protocol}_{IP}_{Port}_{NodeID})
	nodeID := nodeIDFromTag(tag)
	// If we have some rule for this inbound
	if value, ok := r.InboundRule.Load(tag); ok {
		ruleList := value.([]api.DetectRule)
		for _, rule := range ruleList {
			if rule.Pattern.Match([]byte(destination)) {
				// Check if user is exempt from this rule on the current node
				if uid >= 0 && r.isExempt(tag, uid, rule.ID, nodeID) {
					continue
				}
				hitRuleID = rule.ID
				reject = true
				break
			}
		}
		// If we hit some rule
		if reject && hitRuleID != -1 {
			if uid < 0 {
				errors.LogDebug(context.Background(), fmt.Sprintf("Record illegal behavior failed! Cannot find user's uid: %s", userKey))
				return reject
			}
			newSet := mapset.NewSet(api.DetectResult{UID: uid, RuleID: hitRuleID, IP: srcIP})
			// If there are any hit history
			if v, ok := r.InboundDetectResult.LoadOrStore(tag, newSet); ok {
				resultSet := v.(mapset.Set[api.DetectResult])
				// If this is a new record
				if resultSet.Add(api.DetectResult{UID: uid, RuleID: hitRuleID, IP: srcIP}) {
					r.InboundDetectResult.Store(tag, resultSet)
				}
			}
		}
	}
	return reject
}

// DetectUnexempted 供拿不到用户身份的逐包检查使用：只按本节点没有任何豁免的规则拦截，
// 有豁免的规则仍由带身份的审计判定，不能误伤豁免用户。
func (r *Manager) DetectUnexempted(tag string, destination string) bool {
	value, ok := r.InboundRule.Load(tag)
	if !ok {
		return false
	}
	destination = normalizeDestination(destination)
	nodeID := nodeIDFromTag(tag)
	for _, rule := range value.([]api.DetectRule) {
		if rule.Pattern.Match([]byte(destination)) && !r.ruleExempted(tag, rule.ID, nodeID) {
			return true
		}
	}
	return false
}

func (r *Manager) ruleExempted(tag string, ruleID int, nodeID int) bool {
	table, ok := r.exemptUsers.Load(tag)
	if !ok {
		return false
	}
	exempted := false
	table.(*sync.Map).Range(func(uid, _ any) bool {
		exempted = r.isExempt(tag, uid.(int), ruleID, nodeID)
		return !exempted
	})
	return exempted
}

// SingBoxSniffRule 让按 IP 直连的 TLS / HTTP / QUIC 连接也能按其中的域名审计。
// 不改写目标地址：连接仍发往客户端请求的地址，私网拦截照旧按该地址判定。
func SingBoxSniffRule() option.Rule {
	return option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RuleAction: option.RuleAction{
				Action:       C.RuleActionTypeSniff,
				SniffOptions: option.RouteActionSniff{Sniffer: []string{C.ProtocolTLS, C.ProtocolHTTP, C.ProtocolQUIC}},
			},
		},
	}
}

// normalizeDestination 去掉主机名末尾的根点：netflix.com. 与 netflix.com 解析结果相同，不能借此绕过规则
func normalizeDestination(destination string) string {
	if i := strings.LastIndex(destination, ".:"); i >= 0 && isPort(destination[i+2:]) {
		destination = destination[:i] + destination[i+1:]
	}
	return strings.TrimSuffix(destination, ".")
}

func isPort(s string) bool {
	_, err := strconv.ParseUint(s, 10, 16)
	return err == nil
}
