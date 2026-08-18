package tuic

import (
	"sync"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/task"
	"golang.org/x/time/rate"

	"github.com/ECYCloud/ECYCloudNode/api"
	"github.com/ECYCloud/ECYCloudNode/common/limiter"
	"github.com/ECYCloud/ECYCloudNode/common/rule"
	"github.com/ECYCloud/ECYCloudNode/service/controller"
)

type TuicService struct {
	apiClient api.API
	config    *controller.Config

	clientInfo api.ClientInfo
	nodeInfo   *api.NodeInfo

	box        *box.Box
	inboundTag string

	tag     string
	startAt time.Time
	tasks   []periodicTask
	logger  *log.Entry

	rules *rule.Manager

	// globalChecker 跨节点全局设备限制（共享 Redis），未启用时为 nil
	globalChecker *limiter.GlobalDeviceChecker

	mu           sync.RWMutex
	users        map[string]userRecord           // authKey -> user
	traffic      map[string]*userTraffic         // authKey -> counters
	onlineIPs    map[string]map[string]struct{}  // authKey -> set of IPs
	ipLastActive map[string]map[string]time.Time // authKey -> ip -> last active time
	authUsers    []option.TUICUser               // users for sing-box TUIC authentication
	rateLimiters map[string]*rate.Limiter        // authKey -> per-user speed limiter
	// builtAuthUsers 是运行中的 inbound 实际认识的凭据。sing-box 的 TUIC
	// inbound 在构造时就固化用户表且没有在线更新入口，靠它判断是否必须重建。
	builtAuthUsers map[string]struct{}

	// reloadMu prevents concurrent rebuilds of the underlying sing-box
	// instance when node configuration or certificates change.
	reloadMu sync.Mutex

	// Recovery tracking for IP whitelist / connectivity issues
	consecutiveFailures int
	lastFailureTime     time.Time
	recoveryMutex       sync.Mutex
	recoveryInProgress  bool
}

type userRecord struct {
	UID         int
	Email       string
	DeviceLimit int
	SpeedLimit  uint64
}

type userTraffic struct {
	Upload   int64
	Download int64
}

type periodicTask struct {
	tag string
	*task.Periodic
}
