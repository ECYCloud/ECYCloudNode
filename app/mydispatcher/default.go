package mydispatcher

import (
	"context"

	"github.com/xtls/xray-core/common"

	"github.com/ECYCloud/ECYCloudNode/common/limiter"
	"github.com/ECYCloud/ECYCloudNode/common/rule"
)

// DefaultDispatcher 只承载各节点共用的限速器与审计规则，controller 经 Type() 取用；
// 转发由内核的官方 dispatcher 完成，审计、名额、限速与计费都在 controller 的出站包装里执行。
type DefaultDispatcher struct {
	Limiter     *limiter.Limiter
	RuleManager *rule.Manager
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return &DefaultDispatcher{Limiter: limiter.New(), RuleManager: rule.New()}, nil
	}))
}

// Type implements common.HasType for registering as a separate feature,
// not overriding core dispatcher. This avoids type-assertion panics in
// xray-core code that expects *dispatcher.DefaultDispatcher.
func (*DefaultDispatcher) Type() interface{} {
	return Type()
}

// Start implements common.Runnable.
func (*DefaultDispatcher) Start() error {
	return nil
}

// Close implements common.Closable.
func (*DefaultDispatcher) Close() error {
	return nil
}
