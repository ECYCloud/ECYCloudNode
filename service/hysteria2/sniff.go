package hysteria2

import (
	"errors"
	"time"

	"github.com/apernet/hysteria/core/v2/server"
	"github.com/apernet/hysteria/extras/v2/sniff"
)

// 与 sing-box 嗅探默认等待时长一致；服务端先发言的协议最多因此多等这么久。
const sniffTimeout = 300 * time.Millisecond

var errUntracedStream = errors.New("stream not traced")

// sniffHook 按 IP 直连时用 TLS / HTTP / QUIC 中的域名改写目标，审计才能看到域名。
// 内核在 Hook 返回后、流量记账之前就把嗅探读到的首包写给目标，所以 TCP 要在这里按该流的
// 连接身份先审计、再计费，否则首包会送到被禁目标且不计流量。
type sniffHook struct {
	sniff.Sniffer
	svc *Hysteria2Service
}

func (h *sniffHook) TCP(stream server.HyStream, reqAddr *string) ([]byte, error) {
	putback, err := h.Sniffer.TCP(stream, reqAddr)
	if err != nil {
		return nil, err
	}
	value, ok := h.svc.streams.Load(stream)
	if !ok {
		return nil, errUntracedStream
	}
	id := value.(*server.StreamStats).AuthID
	if (&hyEventLogger{svc: h.svc}).auditRequest(id, *reqAddr) {
		return nil, errAuditBlocked
	}
	if len(putback) > 0 && !(&hyTrafficLogger{svc: h.svc}).LogTraffic(id, uint64(len(putback)), 0) {
		// 首包被拒时内核只关这条流，标记连接让下一次流量回调照常断开整条连接
		h.svc.mu.Lock()
		if h.svc.blockedIDs != nil {
			h.svc.blockedIDs[id] = true
		}
		h.svc.mu.Unlock()
		return nil, errDisconnectStream
	}
	return putback, nil
}

var errDisconnectStream = errors.New("traffic refused")
