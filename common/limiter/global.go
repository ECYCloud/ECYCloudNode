package limiter

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/xtls/xray-core/common/errors"
)

// GlobalDeviceChecker 基于共享 Redis 的跨节点设备限制检查器。
// 每个用户对应一个 Hash（"UID|<uid>"），field 为 IP、value 为最近活跃时间
// （unix 秒），所有指向同一 Redis 的节点共同维护一份用户在线 IP 集合。
// 供 Xray 系 limiter 与 Hysteria2 / AnyTLS / TUIC 服务共用。
type GlobalDeviceChecker struct {
	client  *redis.Client
	expiry  int64 // second
	timeout time.Duration
}

var (
	globalCheckerMu sync.Mutex
	globalCheckers  = make(map[GlobalDeviceLimitConfig]*GlobalDeviceChecker)
)

// 名额的读与写必须在 Redis 内一次做完：改成「取回在线表 → 本地增删 → 写回」的话，
// 多节点并发时后写者会覆盖前写者刚登记的 IP，在线数可以超过上限。同理不得在前面
// 垫本地缓存，否则节点会拿过期副本写回。
//
// sweepPrelude 是三个脚本共用的前置片段：清掉过期 field，算出按活跃时间升序的存活
// 列表与本次 IP 的活跃时间。ARGV 顺序固定为 now / expiry / ip / deviceLimit / touch / target。
const sweepPrelude = `
local now = tonumber(ARGV[1])
local expiry = tonumber(ARGV[2])
local ip = ARGV[3]
local entries = redis.call('HGETALL', KEYS[1])
local live = {}
local mine = nil
for i = 1, #entries, 2 do
	local seen = tonumber(entries[i + 1])
	if seen == nil or now - seen > expiry then
		redis.call('HDEL', KEYS[1], entries[i])
	else
		live[#live + 1] = {entries[i], seen}
		if entries[i] == ip then
			mine = seen
		end
	end
end
table.sort(live, function(a, b) return a[2] < b[2] end)
`

// admitScript 在名额未满时登记 IP 并放行（返回 1）；名额已满返回 0，由调用方取得
// 官方客户端确认后再走 evictScript。
var admitScript = redis.NewScript(sweepPrelude + `
local limit = tonumber(ARGV[4])
local touch = tonumber(ARGV[5])
if mine ~= nil then
	if now - mine >= touch then
		redis.call('HSET', KEYS[1], ip, ARGV[1])
		redis.call('EXPIRE', KEYS[1], ARGV[2])
	end
	return 1
end
if #live < limit then
	redis.call('HSET', KEYS[1], ip, ARGV[1])
	redis.call('EXPIRE', KEYS[1], ARGV[2])
	return 1
end
return 0
`)

// evictScript 先挤掉用户选定的 target（不在线则跳过），不够再从最旧的开始补，
// 腾出名额后登记本次 IP，返回被挤下线的 IP 列表。
// 名额在两次往返之间被别的节点释放时不挤任何人，直接登记。
var evictScript = redis.NewScript(sweepPrelude + `
local limit = tonumber(ARGV[4])
local target = ARGV[6]
local kicked = {}
if mine == nil then
	if target ~= '' and target ~= ip and redis.call('HDEL', KEYS[1], target) == 1 then
		kicked[#kicked + 1] = target
		for i = 1, #live do
			if live[i][1] == target then
				table.remove(live, i)
				break
			end
		end
	end
	for i = 1, #live - limit + 1 do
		redis.call('HDEL', KEYS[1], live[i][1])
		kicked[#kicked + 1] = live[i][1]
	end
end
redis.call('HSET', KEYS[1], ip, ARGV[1])
redis.call('EXPIRE', KEYS[1], ARGV[2])
return kicked
`)

// refreshScript 只续期已在名额中的 IP；已被挤出时返回 0，禁止踢人抢回。
var refreshScript = redis.NewScript(sweepPrelude + `
local touch = tonumber(ARGV[5])
if mine == nil then
	return 0
end
if now - mine >= touch then
	redis.call('HSET', KEYS[1], ip, ARGV[1])
	redis.call('EXPIRE', KEYS[1], ARGV[2])
end
return 1
`)

// NewGlobalDeviceChecker 未启用全局限制时返回 nil；nil 检查器的 Allow / Refresh 恒放行。
// 配置相同时必须返回同一实例：Redis 客户端的连接池没有关闭时机，节点信息每次变化
// 重建就会持续泄漏连接。
func NewGlobalDeviceChecker(config *GlobalDeviceLimitConfig) *GlobalDeviceChecker {
	if config == nil || !config.Enable {
		return nil
	}

	globalCheckerMu.Lock()
	defer globalCheckerMu.Unlock()
	if checker, ok := globalCheckers[*config]; ok {
		return checker
	}

	expiry := config.Expiry
	if expiry <= 0 {
		// Expiry 未配置时条目会立即过期、限制失效，回退到示例配置默认值
		expiry = 60
	}
	timeout := config.Timeout
	if timeout <= 0 {
		// Timeout 未配置时 context 立刻到期，每次请求都失败并按放行处理，
		// 等于静默关掉全局限制，同样回退到示例配置默认值
		timeout = 5
	}

	checker := &GlobalDeviceChecker{
		client: redis.NewClient(&redis.Options{
			Network:  config.RedisNetwork,
			Addr:     config.RedisAddr,
			Username: config.RedisUsername,
			Password: config.RedisPassword,
			DB:       config.RedisDB,
		}),
		expiry:  int64(expiry),
		timeout: time.Duration(timeout) * time.Second,
	}
	globalCheckers[*config] = checker
	return checker
}

// Allow 判定 uid 的 ip 是否允许在线（全局口径）。
// 已在线 IP 刷新活跃时间并放行；新 IP 在名额未满时登记放行，超限须已有官方确认才踢人。
func (g *GlobalDeviceChecker) Allow(uid int, ip string, deviceLimit int, grant ReclaimGrant) bool {
	if g == nil || deviceLimit <= 0 {
		return true
	}

	admitted, err := g.eval(admitScript, uid, ip, deviceLimit, "").Int()
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "cache service")
		return true
	}
	if admitted == 1 {
		return true
	}

	// 名额已满。踢人要先拿到官方客户端的确认，而那是一次对面板的 HTTP 调用，
	// 放不进 Lua，只能拆成「判满 → 取确认 → 原子腾位并登记」三步。判满与腾位
	// 各自原子，所以中途被别的节点占了名额也不会超额登记。
	if !grant.Granted {
		if grant = ConsumeReclaimGrant(uid, ip); !grant.Granted {
			return false
		}
	}

	kicked, err := g.eval(evictScript, uid, ip, deviceLimit, grant.TargetIP).StringSlice()
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "cache service")
		return true
	}
	for _, kickedIP := range kicked {
		NoteDeviceKick(uid, kickedIP)
	}
	return true
}

// Refresh 仅续期已在全局名额中的 IP；若已被挤出则返回 false，禁止踢人抢回。
func (g *GlobalDeviceChecker) Refresh(uid int, ip string, deviceLimit int) bool {
	if g == nil || deviceLimit <= 0 {
		return true
	}

	online, err := g.eval(refreshScript, uid, ip, deviceLimit, "").Int()
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "cache service")
		return true
	}
	return online == 1
}

func (g *GlobalDeviceChecker) eval(script *redis.Script, uid int, ip string, deviceLimit int, target string) *redis.Cmd {
	ctx, cancel := context.WithTimeout(context.Background(), g.timeout)
	defer cancel()

	// Run 是同步的，返回时结果已落到 Cmd 上，随后取消 context 不影响取值。
	return script.Run(ctx, g.client, []string{fmt.Sprintf("UID|%d", uid)},
		time.Now().Unix(), g.expiry, ip, deviceLimit, onlineTouchSec, target)
}
