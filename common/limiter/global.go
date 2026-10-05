package limiter

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/xtls/xray-core/common/errors"

	"github.com/ECYCloud/ECYCloudNode/api"
)

// GlobalDeviceChecker 基于共享 Redis 的跨节点设备限制检查器。
// 每个用户对应一个 Hash（"UID|<uid>"），field 为 名额、value 为最近活跃时间
// （unix 秒），所有指向同一 Redis 的节点共同维护一份用户在线 名额 集合。
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

const kickPrelude = `
local slot = ARGV[3]
local authorized = true
if ARGV[9] == '1' then
	local requested = ARGV[7]
	local deadline = tonumber(ARGV[8])
	local stored = redis.call('GET', KEYS[2])
	local previous = '0'
	if stored then
		local untilAt
		previous, untilAt = string.match(stored, '^(%d+)|(%d+)$')
		untilAt = tonumber(untilAt)
		if untilAt == 0 or deadline == 0 then
			deadline = 0
		else
			deadline = math.max(deadline, untilAt)
		end
	end
	local newer = #requested > #previous or (#requested == #previous and requested > previous)
	authorized = requested == previous or newer
	local version = newer and requested or previous
	local value = version .. '|' .. string.format('%.0f', deadline)
	if not stored or stored ~= value then
		if deadline > 0 then
			redis.call('SET', KEYS[2], value, 'EX', math.max(tonumber(ARGV[2]), deadline - tonumber(ARGV[1]) + tonumber(ARGV[2])))
		else
			redis.call('SET', KEYS[2], value)
		end
	end
	if newer then
		redis.call('HDEL', KEYS[1], slot)
	end
end
`

var syncKickScript = redis.NewScript(kickPrelude + `return authorized and 1 or 0`)

// 名额的读与写必须在 Redis 内一次做完：改成「取回在线表 → 本地增删 → 写回」的话，
// 多节点并发时后写者会覆盖前写者刚登记的 名额，在线数可以超过上限。同理不得在前面
// 垫本地缓存，否则节点会拿过期副本写回。
//
// sweepPrelude 是两个脚本共用的前置片段：清掉过期 field，算出按活跃时间升序的存活
// 列表与本次 名额 的活跃时间。ARGV 顺序固定为 now / expiry / slot / deviceLimit / touch / target。
const sweepPrelude = `
local now = tonumber(ARGV[1])
local expiry = tonumber(ARGV[2])
local slot = ARGV[3]
local entries = redis.call('HGETALL', KEYS[1])
local live = {}
local mine = nil
for i = 1, #entries, 2 do
	local seen = tonumber(entries[i + 1])
	if seen == nil or now - seen > expiry then
		redis.call('HDEL', KEYS[1], entries[i])
	else
		live[#live + 1] = {entries[i], seen}
		if entries[i] == slot then
			mine = seen
		end
	end
end
table.sort(live, function(a, b) return a[2] < b[2] end)
`

// admitScript 在名额未满时登记 名额 并放行（返回 1）；名额已满返回 0，Allow 取得
// 官方客户端确认后再走 evictScript，Refresh 据此判为已被挤出。
var admitScript = redis.NewScript(kickPrelude + `
if not authorized then return -1 end
` + sweepPrelude + `
local limit = tonumber(ARGV[4])
local touch = tonumber(ARGV[5])
if mine ~= nil then
	if now - mine >= touch then
		redis.call('HSET', KEYS[1], slot, ARGV[1])
		redis.call('EXPIRE', KEYS[1], ARGV[2])
	end
	return 1
end
if #live < limit then
	redis.call('HSET', KEYS[1], slot, ARGV[1])
	redis.call('EXPIRE', KEYS[1], ARGV[2])
	return 1
end
return 0
`)

// evictScript 先挤掉用户选定的 target（不在线则跳过），不够再从最旧的开始补，
// 腾出名额后登记本次 名额，返回被挤下线的 名额 列表。
// 名额在两次往返之间被别的节点释放时不挤任何人，直接登记。
var evictScript = redis.NewScript(kickPrelude + `
if not authorized then return {'0'} end
` + sweepPrelude + `
local limit = tonumber(ARGV[4])
local target = ARGV[6]
local kicked = {'1'}
if mine == nil then
	if target ~= '' and target ~= slot and redis.call('HDEL', KEYS[1], target) == 1 then
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
redis.call('HSET', KEYS[1], slot, ARGV[1])
redis.call('EXPIRE', KEYS[1], ARGV[2])
return kicked
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

// Allow 判定 uid 的 slot 是否允许在线（全局口径）。
// 已在线 名额 刷新活跃时间并放行；新 名额 在名额未满时登记放行，超限须已有官方确认才踢人。
func (g *GlobalDeviceChecker) Allow(uid int, slot string, deviceLimit int, grant ReclaimGrant, authorization ...UserInfo) bool {
	if g == nil || deviceLimit <= 0 {
		return true
	}

	admitted, err := g.eval(admitScript, uid, slot, deviceLimit, "", authorization...).Int()
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "cache service")
		return true
	}
	if admitted == 1 {
		return true
	}
	if admitted < 0 {
		return false
	}

	// 名额已满。踢人要先拿到官方客户端的确认，而那是一次对面板的 HTTP 调用，
	// 放不进 Lua，只能拆成「判满 → 取确认 → 原子腾位并登记」三步。判满与腾位
	// 各自原子，所以中途被别的节点占了名额也不会超额登记。
	if !grant.Granted {
		if grant = ConsumeReclaimGrant(uid, slot); !grant.Granted {
			return false
		}
	}

	kicked, err := g.eval(evictScript, uid, slot, deviceLimit, grant.TargetSlot, authorization...).StringSlice()
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "cache service")
		return true
	}
	if len(kicked) == 0 || kicked[0] != "1" {
		return false
	}
	for _, kickedSlot := range kicked[1:] {
		NoteDeviceKick(uid, kickedSlot)
	}
	return true
}

// Refresh 续期全局名额中的 名额，闲置过期但尚有空余名额时重新登记；若已被挤出且名额已满
// 则返回 false，禁止踢人抢回。
func (g *GlobalDeviceChecker) Refresh(uid int, slot string, deviceLimit int, authorization ...UserInfo) bool {
	if g == nil || deviceLimit <= 0 {
		return true
	}

	online, err := g.eval(admitScript, uid, slot, deviceLimit, "", authorization...).Int()
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "cache service")
		return true
	}
	return online == 1
}

func (g *GlobalDeviceChecker) SyncUsers(users *[]api.UserInfo) {
	if g == nil || users == nil {
		return
	}
	for _, user := range *users {
		if user.ClientID == 0 {
			continue
		}
		_, err := g.eval(syncKickScript, user.UID, OnlineKey(user.ClientID, ""), 0, "",
			UserInfo{KickVersion: user.KickVersion, ValidUntil: user.ValidUntil}).Int()
		if err != nil {
			errors.LogErrorInner(context.Background(), err, "cache service")
			return
		}
	}
}

func (g *GlobalDeviceChecker) eval(script *redis.Script, uid int, slot string, deviceLimit int, target string, authorization ...UserInfo) *redis.Cmd {
	ctx, cancel := context.WithTimeout(context.Background(), g.timeout)
	defer cancel()

	// 官方客户端与第三方分开记账：两组各自独立使用同一个上限，不互相挤占名额
	redisKey := fmt.Sprintf("UID|%d", uid)
	official := 0
	if IsClientOnlineKey(slot) {
		redisKey += "|client"
		official = 1
	}
	user := UserInfo{}
	if len(authorization) > 0 {
		user = authorization[0]
	}
	// Run 是同步的，返回时结果已落到 Cmd 上，随后取消 context 不影响取值。
	return script.Run(ctx, g.client, []string{redisKey, redisKey + "|kick|" + slot},
		time.Now().Unix(), g.expiry, slot, deviceLimit, onlineTouchSec, target,
		strconv.FormatUint(user.KickVersion, 10), user.ValidUntil, official)
}
