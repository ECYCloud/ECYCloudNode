package anytls

import (
	"context"
	"net"
	"strings"
	"sync"

	protocol "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type deviceInbound struct {
	inbound.Adapter
	listener *listener.Listener
	tls      tls.ServerConfig
	router   adapter.ConnectionRouterEx
	logger   log.ContextLogger
	padding  []byte
	mu       sync.RWMutex
	protocol *protocol.Service
}

func newDeviceInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AnyTLSInboundOptions) (adapter.Inbound, error) {
	h := &deviceInbound{Adapter: inbound.NewAdapter("anytls", tag), router: uot.NewRouter(router, logger), logger: logger, padding: padding.DefaultPaddingScheme}
	if len(options.PaddingScheme) > 0 {
		h.padding = []byte(strings.Join(options.PaddingScheme, "\n"))
	}
	var err error
	if options.TLS != nil && options.TLS.Enabled {
		h.tls, err = tls.NewServer(ctx, logger, *options.TLS)
		if err != nil {
			return nil, err
		}
	}
	h.listener = listener.New(listener.Options{Context: ctx, Logger: logger, Network: []string{N.NetworkTCP}, Listen: options.ListenOptions, ConnectionHandler: h})
	if err := h.UpdateUsers(options.Users); err != nil {
		return nil, err
	}
	return h, nil
}

func (h *deviceInbound) UpdateUsers(users []option.AnyTLSUser) error {
	entries := make([]protocol.User, len(users))
	for i, user := range users {
		entries[i] = protocol.User{Name: user.Name, Password: user.Password}
	}
	next, err := protocol.NewService(protocol.ServiceConfig{Users: entries, PaddingScheme: h.padding, Handler: h, Logger: h.logger})
	if err != nil {
		return err
	}
	h.mu.Lock()
	h.protocol = next
	h.mu.Unlock()
	return nil
}

func (h *deviceInbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.tls != nil {
		if err := h.tls.Start(); err != nil {
			return err
		}
		scope.Add(h.tls.Close)
	}
	if err := h.listener.Start(); err != nil {
		return err
	}
	scope.Add(h.listener.Close)
	return nil
}

func (h *deviceInbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if h.tls != nil {
		next, err := tls.ServerHandshake(ctx, conn, h.tls)
		if err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			return
		}
		conn = next
	}
	h.mu.RLock()
	current := h.protocol
	h.mu.RUnlock()
	if err := current.NewConnection(adapter.WithContext(ctx, &metadata), conn, metadata.Source, onClose); err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
	}
}

func (h *deviceInbound) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	user, _ := auth.UserFromContext[string](ctx)
	h.router.RouteConnectionEx(ctx, conn, adapter.InboundContext{Inbound: h.Tag(), InboundType: h.Type(), InboundDetour: h.listener.ListenOptions().Detour, Source: source, Destination: destination.Unwrap(), User: user}, onClose)
}

func (s *AnyTLSService) updateInboundUsers() error {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	if s.closed || s.box == nil {
		return nil
	}
	h, ok := s.box.Inbound().Get(s.inboundTag)
	if !ok {
		return nil
	}
	s.mu.RLock()
	users := append([]option.AnyTLSUser(nil), s.authUsers...)
	s.mu.RUnlock()
	if err := h.(*deviceInbound).UpdateUsers(users); err != nil {
		return err
	}
	s.recordBuiltUsers(users)
	return nil
}

func (s *AnyTLSService) recordBuiltUsers(users []option.AnyTLSUser) {
	built := make(map[string]struct{}, len(users))
	for _, user := range users {
		built[user.Name] = struct{}{}
	}
	s.mu.Lock()
	s.builtAuthUsers = built
	s.mu.Unlock()
}
