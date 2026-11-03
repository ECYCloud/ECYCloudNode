package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xlog "github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"

	"github.com/ECYCloud/ECYCloudNode/api"
	"github.com/ECYCloud/ECYCloudNode/app/mydispatcher"
	"github.com/ECYCloud/ECYCloudNode/common/limiter"
)

func (c *Controller) removeInbound(tag string) error {
	err := c.ibm.RemoveHandler(context.Background(), tag)
	return err
}

// ecycloudNodeManagedPrefixes defines all protocol prefixes that ECYCloudNode manages.
// Tags with these prefixes follow the format: {Protocol}_{IP}_{Port}_{NodeID}
var ecycloudNodeManagedPrefixes = []string{
	"VLESS_",
	"Trojan_",
	"Vmess_",
	"Shadowsocks_",
}

// isECYCloudNodeManagedTag checks if a tag is managed by ECYCloudNode (i.e., it belongs to a specific node).
// ECYCloudNode-managed tags have the format: {Protocol}_{IP}_{Port}_{NodeID}
func isECYCloudNodeManagedTag(tag string) bool {
	for _, prefix := range ecycloudNodeManagedPrefixes {
		if strings.HasPrefix(tag, prefix) {
			return true
		}
	}
	return false
}

type auditDetector interface {
	Detect(tag string, destination string, email string, srcIP string) bool
}

// dataPathWrapper wraps outbound.Handler to enforce device limit, user/node speed limit,
// audit rules and ensure userland path is used for stats.
type dataPathWrapper struct {
	outbound.Handler
	pm      policy.Manager
	sm      stats.Manager
	limiter *limiter.Limiter
	// ruleMgr provides audit detection
	ruleMgr auditDetector
	// tag identifies this node/inbound tag for limiter and rules
	tag string
	// obm allows us to look up the correct outbound handler by tag, so we can
	// enforce "same node in, same node out" routing without touching xray-core
	// dispatcher internals.
	obm outbound.Manager
}

// Tag returns the outbound tag. This MUST match the inbound tag to ensure
// correct routing (same NodeID in, same NodeID out).
func (w *dataPathWrapper) Tag() string {
	return w.tag
}

func (w *dataPathWrapper) Dispatch(ctx context.Context, link *transport.Link) {
	// Force userland path to keep stats/limit in effect
	if sess := session.InboundFromContext(ctx); sess != nil {
		sess.CanSpliceCopy = 3
	}

	// --- FIRST: Enforce "same node in, same node out" semantics -------------
	// 对所有 ECYCloudNode 管理的节点做强制校验：入站 tag 必须和出站 tag 完全一致，
	// 防止流量串到其他节点或协议上。
	// 支持的协议: VLESS, Trojan, Vmess, Shadowsocks
	if sess := session.InboundFromContext(ctx); sess != nil {
		inTag := sess.Tag
		if isECYCloudNodeManagedTag(inTag) && inTag != "" && inTag != w.tag {
			// Try to find the correct outbound for this ECYCloudNode inbound tag.
			if w.obm != nil {
				if h := w.obm.GetHandler(inTag); h != nil {
					// Avoid infinite recursion if, for some reason, the manager returns
					// the same wrapper instance.
					if h == w {
						log.WithFields(log.Fields{
							"inbound_tag":  inTag,
							"outbound_tag": w.tag,
						}).Warn("same-node routing: manager returned current outbound; using it directly")
						// Fall through to process in this wrapper
					} else {
						// Update access log detour to reflect the actual same-node outbound
						// selection (e.g., Trojan_x => Trojan_x) instead of the originally chosen
						// different outbound recorded by core dispatcher.
						if am := xlog.AccessMessageFromContext(ctx); am != nil {
							am.Detour = inTag + " => " + h.Tag()
						}
						log.WithFields(log.Fields{
							"inbound_tag":       inTag,
							"selected_outbound": w.tag,
							"reroute_outbound":  h.Tag(),
						}).Info("same-node routing: rerouting to outbound with matching tag")
						// Delegate to the correct handler and stop processing in current wrapper.
						// The correct wrapper will handle audit/limiter with the right node tag.
						h.Dispatch(ctx, link)
						return
					}
				} else {
					log.WithFields(log.Fields{
						"inbound_tag":  inTag,
						"outbound_tag": w.tag,
					}).Error("same-node routing: no outbound handler found for inbound tag; rejecting connection")
					common.Close(link.Writer)
					common.Interrupt(link.Reader)
					return
				}
			} else {
				log.WithFields(log.Fields{
					"inbound_tag":  inTag,
					"outbound_tag": w.tag,
				}).Error("same-node routing: outbound manager is nil; rejecting connection")
				common.Close(link.Writer)
				common.Interrupt(link.Reader)
				return
			}
		}
	}

	// --- Now we're in the correct wrapper (inTag matches w.tag) -------------
	// Perform audit and rate limiting with the correct node tag.
	if !guardDataPath(ctx, link, w.tag, w.limiter, w.ruleMgr) {
		return
	}

	// Normal path: inbound tag matches this node's tag, dispatch to actual handler.
	w.Handler.Dispatch(ctx, link)
}

// guardDataPath 返回 false 表示连接已被审计或名额拒绝，链路已关闭。
func guardDataPath(ctx context.Context, link *transport.Link, nodeTag string, lim *limiter.Limiter, ruleMgr auditDetector) bool {
	sess := session.InboundFromContext(ctx)
	if sess == nil || sess.User == nil {
		return true
	}
	email := sess.User.Email
	srcIP := sess.Source.Address.IP().String()
	// Resolve destination from session
	var destStr string
	var udp bool
	if outs := session.OutboundsFromContext(ctx); len(outs) > 0 {
		ob := outs[len(outs)-1]
		destStr = ob.Target.String()
		udp = ob.Target.Network == xnet.Network_UDP
	}

	// Audit check: reject immediately on hit
	if ruleMgr != nil && email != "" && destStr != "" {
		if ruleMgr.Detect(nodeTag, destStr, email, srcIP) {
			// Log audit rule hit with destination and user info for all protocols.
			log.WithFields(log.Fields{
				"tag":   nodeTag,
				"user":  email,
				"srcIP": srcIP,
				"dest":  destStr,
			}).Warn("audit rule hit, closing connection")
			// close link
			common.Close(link.Writer)
			common.Interrupt(link.Reader)
			return false
		}
	}

	// 全锥 UDP 的后续包带各自的目标（XUDP、Trojan、Shadowsocks 的逐包地址），上面只审计了首个目标
	if udp && ruleMgr != nil && email != "" {
		link.Reader = &udpAuditReader{Reader: link.Reader, blocked: func(dest string) bool { return ruleMgr.Detect(nodeTag, dest, email, srcIP) }}
	}

	// Device limit and rate limit
	if lim != nil && email != "" {
		if _, _, reject := lim.GetUserBucket(nodeTag, email, srcIP); reject {
			common.Close(link.Writer)
			common.Interrupt(link.Reader)
			return false
		}
		link.Reader = lim.RateReader(link.Reader, nodeTag, email)
		if record := lim.TrafficRecorder(nodeTag, email); record != nil {
			link.Reader = &mydispatcher.SizeStatReader{Reader: link.Reader, Record: func(n int64) error { return record(n, 0) }}
			link.Writer = &mydispatcher.SizeStatWriter{Writer: link.Writer, Record: func(n int64) error { return record(0, n) }}
		}
		// 存活连接周期复查在线名额，超限被挤出的 IP 会被强制断开；
		// 上行（客户端数据）续期在线时间，下行只核查不续期
		kickVersion := lim.KickVersion(nodeTag, email)
		link.Reader = lim.GuardReader(link.Reader, nodeTag, email, srcIP, kickVersion)
		link.Writer = lim.GuardWriter(link.Writer, nodeTag, email, srcIP, kickVersion)
		link.Writer = lim.RateWriter(link.Writer, nodeTag, email)
	}
	return true
}

const maxAuditedTargets = 256

// udpAuditReader 丢弃发往被审计规则命中目标的 UDP 包；放在计费与限速之内，丢弃的包不计流量。
type udpAuditReader struct {
	buf.Reader
	blocked  func(dest string) bool
	verdicts map[string]bool
}

func (r *udpAuditReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	kept := mb[:0]
	for _, b := range mb {
		if b.UDP != nil && r.isBlocked(b.UDP.String()) {
			b.Release()
			continue
		}
		kept = append(kept, b)
	}
	return kept, err
}

func (r *udpAuditReader) isBlocked(dest string) bool {
	if blocked, ok := r.verdicts[dest]; ok {
		return blocked
	}
	blocked := r.blocked(dest)
	if r.verdicts == nil || len(r.verdicts) >= maxAuditedTargets {
		r.verdicts = make(map[string]bool)
	}
	r.verdicts[dest] = blocked
	return blocked
}

// customOutboundWrapper 包装 custom_outbound.json 的出站：内核路由把 RouteConfigPath 的规则排在
// 同节点规则之前，受管入站的连接可能直接落到这些出站，必须同样审计、占名额、限速与计费。
type customOutboundWrapper struct {
	outbound.Handler
	limiter *limiter.Limiter
	ruleMgr auditDetector
}

func (w *customOutboundWrapper) Dispatch(ctx context.Context, link *transport.Link) {
	if sess := session.InboundFromContext(ctx); sess != nil && isECYCloudNodeManagedTag(sess.Tag) {
		sess.CanSpliceCopy = 3
		if !guardDataPath(ctx, link, sess.Tag, w.limiter, w.ruleMgr) {
			return
		}
	}
	w.Handler.Dispatch(ctx, link)
}

// AddCustomOutbounds 按配置顺序加入自定义出站，首个仍是内核默认出站。
func AddCustomOutbounds(server *core.Instance, configs []*core.OutboundHandlerConfig) error {
	obm, ok := server.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if !ok {
		return fmt.Errorf("outbound manager not registered")
	}
	md, ok := server.GetFeature(mydispatcher.Type()).(*mydispatcher.DefaultDispatcher)
	if !ok {
		return fmt.Errorf("mydispatcher not registered")
	}
	for _, config := range configs {
		rawHandler, err := core.CreateObject(server, config)
		if err != nil {
			return err
		}
		handler, ok := rawHandler.(outbound.Handler)
		if !ok {
			return fmt.Errorf("not an OutboundHandler: %s", config.Tag)
		}
		if err := obm.AddHandler(context.Background(), &customOutboundWrapper{Handler: handler, limiter: md.Limiter, ruleMgr: md.RuleManager}); err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) removeOutbound(tag string) error {
	err := c.obm.RemoveHandler(context.Background(), tag)
	return err
}

func (c *Controller) addInbound(config *core.InboundHandlerConfig) error {
	rawHandler, err := core.CreateObject(c.server, config)
	if err != nil {
		return err
	}
	handler, ok := rawHandler.(inbound.Handler)
	if !ok {
		return fmt.Errorf("not an InboundHandler: %s", err)
	}
	if err := c.ibm.AddHandler(context.Background(), handler); err != nil {
		return err
	}
	return nil
}

func (c *Controller) addOutbound(config *core.OutboundHandlerConfig) error {
	rawHandler, err := core.CreateObject(c.server, config)
	if err != nil {
		return err
	}
	handler, ok := rawHandler.(outbound.Handler)
	if !ok {
		return fmt.Errorf("not an InboundHandler: %s", err)
	}
	// Wrap outbound handler to enforce audit/device limit/rate limit, keep stats
	// path, and enforce "same node in, same node out" semantics.
	wrapper := &dataPathWrapper{
		Handler: handler,
		pm:      c.pm,
		sm:      c.stm,
		limiter: c.dispatcher.Limiter,
		ruleMgr: c.dispatcher.RuleManager,
		// Each controller instance has a unique Tag derived from NodeID, so using
		// c.Tag here ensures per-node isolation for limiter/rules *and* routing.
		tag: c.Tag,
		obm: c.obm,
	}
	log.Infof("Adding outbound handler: configTag=%s handlerTag=%s wrapperTag=%s controllerTag=%s", config.Tag, handler.Tag(), wrapper.Tag(), c.Tag)
	if err := c.obm.AddHandler(context.Background(), wrapper); err != nil {
		return err
	}
	return nil
}

func (c *Controller) addUsers(users []*protocol.User, tag string) error {
	handler, err := c.ibm.GetHandler(context.Background(), tag)
	if err != nil {
		return fmt.Errorf("no such inbound tag: %s", err)
	}
	inboundInstance, ok := handler.(proxy.GetInbound)
	if !ok {
		return fmt.Errorf("handler %s has not implemented proxy.GetInbound", tag)
	}

	userManager, ok := inboundInstance.GetInbound().(proxy.UserManager)
	if !ok {
		return fmt.Errorf("handler %s has not implemented proxy.UserManager", tag)
	}
	for _, item := range users {
		// 上一轮可能只加上了一部分，已在的跳过，不能因「已存在」中止整批
		if userManager.GetUser(context.Background(), item.Email) != nil {
			continue
		}
		mUser, err := item.ToMemoryUser()
		if err == nil {
			err = userManager.AddUser(context.Background(), mUser)
		}
		if err != nil {
			// 单个用户凭据有误不能连累其余用户，也不能让重建停在装好 inbound 却没有限速器的状态；
			// 面板改正凭据后用户标识随之变化，会作为新用户重新加入
			c.logger.Errorf("Add user %s failed: %s", item.Email, err)
			continue
		}
		// Pre-register per-user traffic counters so core can increment them (downlink/uplink)
		uName, dName := trafficCounters(mUser.Email)
		c.stm.GetOrRegisterCounter(uName)
		c.stm.GetOrRegisterCounter(dName)
	}
	return nil
}

func (c *Controller) removeUsers(users []string, tag string) error {
	handler, err := c.ibm.GetHandler(context.Background(), tag)
	if err != nil {
		return fmt.Errorf("no such inbound tag: %s", err)
	}
	inboundInstance, ok := handler.(proxy.GetInbound)
	if !ok {
		return fmt.Errorf("handler %s is not implement proxy.GetInbound", tag)
	}

	userManager, ok := inboundInstance.GetInbound().(proxy.UserManager)
	if !ok {
		return fmt.Errorf("handler %s is not implement proxy.UserManager", err)
	}
	var removeErr error
	for _, email := range users {
		// 已不在的视为删除成功，重试时继续处理其余用户
		if userManager.GetUser(context.Background(), email) != nil {
			if err := userManager.RemoveUser(context.Background(), email); err != nil {
				removeErr = errors.Join(removeErr, err)
				continue
			}
		}
		c.unregisterTraffic(email)
	}
	return removeErr
}

// trafficCounters 是 xray 按用户统计上下行的计数器名。
func trafficCounters(email string) (string, string) {
	return "user>>>" + email + ">>>traffic>>>uplink", "user>>>" + email + ">>>traffic>>>downlink"
}

// unregisterTraffic 注销已移除用户的计数器：统计表不会自行清理，用户每次增删或换凭据都会留下一对。
func (c *Controller) unregisterTraffic(email string) {
	uName, dName := trafficCounters(email)
	c.stm.UnregisterCounter(uName)
	c.stm.UnregisterCounter(dName)
}

func (c *Controller) getTraffic(email string) (up int64, down int64) {
	upName, downName := trafficCounters(email)
	if counter := c.stm.GetCounter(upName); counter != nil {
		up = counter.Set(0)
	}
	if counter := c.stm.GetCounter(downName); counter != nil {
		down = counter.Set(0)
	}
	return up, down
}

func (c *Controller) AddInboundLimiter(tag string, nodeSpeedLimit uint64, userList *[]api.UserInfo, globalDeviceLimitConfig *limiter.GlobalDeviceLimitConfig) error {
	var record func(int, int64, int64, ...string) error
	if !c.config.DisableUploadTraffic {
		record = c.apiClient.RecordUserTraffic
	}
	err := c.dispatcher.Limiter.AddInboundLimiter(tag, nodeSpeedLimit, userList, globalDeviceLimitConfig, record)
	limiter.SetReclaimConsumer(tag, limiter.PanelReclaim(c.apiClient))
	return err
}

func (c *Controller) UpdateInboundLimiter(tag string, updatedUserList *[]api.UserInfo, replace ...bool) error {
	err := c.dispatcher.Limiter.UpdateInboundLimiter(tag, updatedUserList, replace...)
	return err
}

func (c *Controller) DeleteInboundLimiter(tag string) error {
	err := c.dispatcher.Limiter.DeleteInboundLimiter(tag)
	limiter.SetReclaimConsumer(tag, nil)
	return err
}

func (c *Controller) GetOnlineDevice(tag string) (*[]api.OnlineUser, error) {
	return c.dispatcher.Limiter.GetOnlineDevice(tag)
}

func (c *Controller) UpdateRule(tag string, newRuleList []api.DetectRule) error {
	err := c.dispatcher.RuleManager.UpdateRule(tag, newRuleList)
	return err
}

func (c *Controller) GetDetectResult(tag string) (*[]api.DetectResult, error) {
	return c.dispatcher.RuleManager.GetDetectResult(tag)
}
