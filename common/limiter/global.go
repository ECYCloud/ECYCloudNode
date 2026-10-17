package limiter

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/xtls/xray-core/common/errors"

	"github.com/ECYCloud/ECYCloudNode/api"
)

// GlobalDeviceChecker 基于共享 Redis 的跨节点设备限制检查器。
// 每个用户对应一个 Hash，官方客户端按设备保存下线序号及各节点租约，
// 第三方按 IP 保存最近活跃时间；共享同一 Redis 的节点共同维护在线名额。
// 供 Xray 系 limiter 与 Hysteria2 / AnyTLS / TUIC 服务共用。
type GlobalDeviceChecker struct {
	client        *redis.Client
	expiry        int64 // second
	timeout       time.Duration
	syncMu        sync.Mutex
	users         map[string]map[int]api.UserInfo
	pending       map[string][]api.UserInfo
	dirty         atomic.Bool
	policyVersion atomic.Uint64
	verified      sync.Map
	clockOffset   atomic.Int64
	cleanupOnce   sync.Once
	cleanupStop   chan struct{}
	cleanupDone   chan struct{}
}

type verifiedSlot struct {
	version uint64
	limit   int
	until   time.Time
}

var (
	globalCheckerMu sync.Mutex
	globalCheckers  = make(map[GlobalDeviceLimitConfig]*GlobalDeviceChecker)
)

const slotPrelude = `
local function readSlot(value)
	if not value then return nil end
	if string.sub(value, 1, 1) == '{' then return cjson.decode(value) end
	local seen, version = string.match(value, '^(-?%d+)|(%d+)$')
	seen = tonumber(seen or value)
	if not seen then return nil end
	return {v = version, leases = {['\0'] = {seen = seen, expires = 0}}}
end
`

const kickPrelude = slotPrelude + `
local slot = ARGV[3]
local authorized = true
if ARGV[9] == '1' then
	local function newerThan(a, b)
		return #a > #b or (#a == #b and a > b)
	end
	local requested = ARGV[7]
	local deadline = tonumber(ARGV[8])
	local retained = deadline == 0 and 0 or deadline * 1000 + tonumber(ARGV[16])
	local stored = redis.call('GET', KEYS[2])
	local previous = '0'
	if stored then
		local untilAt
		previous, untilAt = string.match(stored, '^([^|]+)|(%d+)|panel$')
		if not previous then
			previous, untilAt = string.match(stored, '^(%d+)|(%d+)$')
			if previous then
				untilAt = tonumber(untilAt) == 0 and 0 or tonumber(untilAt) * 1000 + tonumber(ARGV[16])
			else previous, untilAt = 'revoked', 0 end
		end
		untilAt = tonumber(untilAt)
		if untilAt == 0 or retained == 0 then retained = 0
		else retained = math.max(retained, untilAt) end
	end
	local online = readSlot(redis.call('HGET', KEYS[1], slot))
	local onlineVersion = online and online.v
	if ARGV[10] == '1' or previous == 'revoked' then
		redis.call('SET', KEYS[2], 'revoked|' .. string.format('%.0f', retained) .. '|panel')
		if ARGV[10] == '1' then redis.call('HDEL', KEYS[1], slot) end
		authorized = false
	else
	if onlineVersion and newerThan(onlineVersion, previous) then previous = onlineVersion end
	local newer = newerThan(requested, previous)
	authorized = requested == previous or newer
	local version = newer and requested or previous
	local value = version .. '|' .. string.format('%.0f', retained) .. '|panel'
	if not stored or stored ~= value then
		redis.call('SET', KEYS[2], value)
	else redis.call('PERSIST', KEYS[2]) end
	if (stored or onlineVersion) and newer then
		redis.call('HDEL', KEYS[1], slot)
	end
	end
end
`

const policyPrelude = `
local deadline = tonumber(ARGV[8])
local syncedLimit = nil
local policy = redis.call('GET', KEYS[3])
if policy then
	local untilAt
	syncedLimit, untilAt = string.match(policy, '^(-?%d+)|(-?%d+)$')
	syncedLimit = tonumber(syncedLimit)
	deadline = tonumber(untilAt)
else
	local entry = readSlot(redis.call('HGET', KEYS[1], ARGV[3]))
	local lease = entry and entry.leases[ARGV[14]]
	if lease then
		deadline = lease.expires == 0 and 0 or (lease.expires - tonumber(ARGV[16])) / 1000
		syncedLimit = lease.limit
	end
end
if deadline ~= 0 and deadline <= tonumber(ARGV[1]) then authorized = false end
local expiring = deadline ~= 0 and deadline * 1000 <= tonumber(ARGV[12]) + tonumber(ARGV[13])
local scopeExpiry = deadline == 0 and 0 or deadline * 1000 + tonumber(ARGV[16])
local function onlineLimit()
	local limit = tonumber(ARGV[4])
	if syncedLimit then
		if syncedLimit <= 0 then return 0 end
		limit = math.max(limit, syncedLimit)
	end
	return limit
end
`

// 官方在线账本不使用 Redis 墙上时间过期；旧基准只迁移一次，保留原名额。
const ledgerPrelude = `
if ARGV[9] == '1' then
	local key = KEYS[1] .. '|clock'
	if redis.call('GET', key) ~= 'panel' then
		local entries = redis.call('HGETALL', KEYS[1])
		for i = 1, #entries, 2 do
			local entry = readSlot(entries[i + 1])
			if entry then
				for _, lease in pairs(entry.leases) do lease.seen = tonumber(ARGV[15]) end
				redis.call('HSET', KEYS[1], entries[i], cjson.encode(entry))
			end
		end
	end
	if redis.call('EXISTS', KEYS[1]) == 1 then
		redis.call('PERSIST', KEYS[1])
		redis.call('SET', key, 'panel')
	end
end
`

var syncKickScript = redis.NewScript(`
local syncKeys = KEYS
local syncArgs = ARGV
for i = 1, #syncKeys, 3 do
	local offset = (i - 1) / 3 * 6 + 5
	local KEYS = {syncKeys[i], syncKeys[i + 1], syncKeys[i + 2]}
	local ARGV = {syncArgs[1], syncArgs[2], syncArgs[offset], 0, 0, '', syncArgs[offset + 1], syncArgs[offset + 2], '1', syncArgs[offset + 3]}
	ARGV[16] = syncArgs[4]
` + kickPrelude + `
local entry = readSlot(redis.call('HGET', KEYS[1], slot))
if entry and entry.leases[syncArgs[3]] then
	if syncArgs[offset + 5] == '1' then
		entry.leases[syncArgs[3]] = nil
	elseif authorized then
		local limit, untilAt = string.match(syncArgs[offset + 4], '^(-?%d+)|(-?%d+)$')
		entry.leases[syncArgs[3]].expires = tonumber(untilAt) == 0 and 0 or tonumber(untilAt) * 1000 + tonumber(syncArgs[4])
		entry.leases[syncArgs[3]].limit = tonumber(limit)
	end
	if next(entry.leases) then redis.call('HSET', KEYS[1], slot, cjson.encode(entry))
	else redis.call('HDEL', KEYS[1], slot) end
end
if syncArgs[offset + 5] == '1' then
	redis.call('DEL', KEYS[3])
elseif authorized then
	local key = KEYS[3]
	redis.call('SET', key, syncArgs[offset + 4])
end
end
return 1
`)

// 名额的读与写必须在 Redis 内一次做完：改成「取回在线表 → 本地增删 → 写回」的话，
// 多节点并发时后写者会覆盖前写者刚登记的 名额，在线数可以超过上限。同理不得在前面
// 垫本地缓存，否则节点会拿过期副本写回。
//
// sweepPrelude 是两个脚本共用的前置片段：清掉过期 field，算出按活跃时间升序的存活
// 列表与本次 名额 的活跃时间。ARGV 顺序固定为 now / expiry / slot / deviceLimit / touch / target。
const sweepPrelude = `
local now = tonumber(ARGV[1])
if ARGV[9] == '1' then now = tonumber(ARGV[15]) end
local expiry = tonumber(ARGV[2])
local slot = ARGV[3]
local entries = redis.call('HGETALL', KEYS[1])
local live = {}
local mine = nil
local mineEntry = nil
for i = 1, #entries, 2 do
	local entry = ARGV[9] == '1' and readSlot(entries[i + 1]) or nil
	local seen = nil
	if not entry then seen = tonumber(entries[i + 1]) end
	if entry then
		local changed = false
		for owner, lease in pairs(entry.leases) do
			if now - lease.seen > (lease.idle or expiry) or (lease.expires ~= 0 and lease.expires <= tonumber(ARGV[12]) + tonumber(ARGV[16])) then
				entry.leases[owner] = nil
				changed = true
			else seen = math.max(seen or lease.seen, lease.seen) end
		end
		if changed and seen then redis.call('HSET', KEYS[1], entries[i], cjson.encode(entry)) end
	end
	if seen == nil or (not entry and now - seen > expiry) then
		redis.call('HDEL', KEYS[1], entries[i])
	else
		live[#live + 1] = {entries[i], seen}
		if entries[i] == slot then
			mine = seen
			mineEntry = entry
		end
	end
end
table.sort(live, function(a, b) return a[2] < b[2] end)
local function touchSlot()
	if ARGV[9] == '1' then
		local entry = mineEntry or {leases = {}}
		entry.v = ARGV[7]
		entry.leases[ARGV[14]] = {seen = now, expires = scopeExpiry or 0, idle = expiry, limit = tonumber(ARGV[4])}
		redis.call('HSET', KEYS[1], slot, cjson.encode(entry))
		redis.call('PERSIST', KEYS[1])
		redis.call('SET', KEYS[1] .. '|clock', 'panel')
	else
		redis.call('HSET', KEYS[1], slot, now)
		redis.call('EXPIRE', KEYS[1], ARGV[2])
	end
end
`

// admitScript 在名额未满时登记并放行（返回 1）；名额已满返回 0，Allow 取得
// 官方客户端确认后再走 evictScript，Refresh 据此判为已被挤出。
var admitScript = redis.NewScript(kickPrelude + ledgerPrelude + policyPrelude + `
if not authorized then return -1 end
` + sweepPrelude + `
local limit = onlineLimit()
if limit <= 0 then return 1 end
local touch = math.min(tonumber(ARGV[5]), math.max(1, math.floor(expiry / 2)))
if mine ~= nil then
	local own = mineEntry and mineEntry.leases[ARGV[14]]
	if (ARGV[9] == '1' and (not own or own.expires ~= scopeExpiry)) or now - (own and own.seen or mine) >= touch then
		touchSlot()
	end
	return 1
end
if #live < limit then
	touchSlot()
	return 1
end
return 0
`)

var verifyScript = redis.NewScript(kickPrelude + ledgerPrelude + policyPrelude + `
if not authorized then return -1 end
` + sweepPrelude + `
local limit = onlineLimit()
if limit <= 0 or mine ~= nil or #live < limit then return 1 end
return 0
`)

// evictScript 先挤掉用户选定的 target（不在线则跳过），不够再从最旧的开始补，
// 腾出名额后登记本次 名额，返回被挤下线的 名额 列表。
// 名额在两次往返之间被别的节点释放时不挤任何人，直接登记。
var evictScript = redis.NewScript(kickPrelude + ledgerPrelude + policyPrelude + `
if not authorized then return {'0'} end
if syncedLimit and syncedLimit ~= tonumber(ARGV[4]) then return {'0'} end
` + sweepPrelude + `
local limit = tonumber(ARGV[4])
local target = ARGV[6]
local kicked = {'1'}
if mine == nil and #live >= limit then
	if ARGV[11] ~= '1' or expiring then return {'0'} end
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
touchSlot()
return kicked
`)

var cleanupScript = redis.NewScript(slotPrelude + `
if string.find(KEYS[1], '|kick|', 1, true) then
	local policy = string.find(KEYS[1], '|limit|', 1, true)
	if policy then
		if redis.call('EXISTS', string.sub(KEYS[1], 1, policy - 1)) == 0 then redis.call('DEL', KEYS[1]) end
	else
		local value = redis.call('GET', KEYS[1])
		local retained = value and tonumber(string.match(value, '|(%d+)|panel$'))
		if retained and retained > 0 and retained + tonumber(ARGV[2]) * 1000 <= tonumber(ARGV[12]) then redis.call('DEL', KEYS[1]) end
	end
	return 0
end
if redis.call('GET', KEYS[2]) ~= 'panel' then return 0 end
` + sweepPrelude + `
if #live == 0 then redis.call('DEL', KEYS[2]) end
return #live
`)

// NewGlobalDeviceChecker 未启用全局数量限制时返回 nil；授权检查仍独立执行。
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
			Network:               config.RedisNetwork,
			Addr:                  config.RedisAddr,
			Username:              config.RedisUsername,
			Password:              config.RedisPassword,
			DB:                    config.RedisDB,
			ContextTimeoutEnabled: true,
		}),
		expiry:      int64(expiry),
		timeout:     time.Duration(timeout) * time.Second,
		cleanupStop: make(chan struct{}),
		cleanupDone: make(chan struct{}),
	}
	globalCheckers[*config] = checker
	return checker
}

// Allow 判定 uid 的 slot 是否允许在线（全局口径）。
// 已在线 名额 刷新活跃时间并放行；新 名额 在名额未满时登记放行，超限须已有官方确认才踢人。
func (g *GlobalDeviceChecker) Allow(uid int, slot string, deviceLimit int, grant ReclaimGrant, authorization ...UserInfo) bool {
	return g.check(uid, slot, deviceLimit, grant, true, nil, "", authorization...)
}

func (g *GlobalDeviceChecker) CheckCurrent(uid int, slot string, user UserInfo, reclaim bool, current func() (int, bool), scope ...string) bool {
	deviceLimit, authorized := current()
	key := ""
	if len(scope) > 0 {
		key = scope[0]
	}
	return authorized && g.check(uid, slot, deviceLimit, ReclaimGrant{}, reclaim, current, key, user)
}

func (g *GlobalDeviceChecker) check(uid int, slot string, deviceLimit int, grant ReclaimGrant, reclaim bool, current func() (int, bool), scope string, authorization ...UserInfo) (allowed bool) {
	defer func() {
		if !allowed {
			return
		}
		if current != nil {
			_, allowed = current()
		} else if len(authorization) > 0 && authorization[0].ValidUntil != 0 {
			allowed = time.Now().Unix() < authorization[0].ValidUntil
		}
	}()
	if g == nil || deviceLimit <= 0 {
		return true
	}
	if !g.syncPending() {
		return true
	}
	g.verified.Delete(fmt.Sprintf("%d|%s", uid, slot))

	for {
		policyVersion := g.policyVersion.Load()
		admitted, err := g.eval(admitScript, uid, slot, deviceLimit, "", false, scope, authorization...).Int()
		if err != nil {
			errors.LogErrorInner(context.Background(), err, "cache service")
			return true
		}
		if admitted == 1 {
			return true
		}
		if admitted < 0 {
			if current != nil {
				latest, authorized := current()
				if authorized && (latest != deviceLimit || g.policyVersion.Load() != policyVersion) {
					return g.check(uid, slot, latest, grant, reclaim, current, scope, authorization...)
				}
			}
			return false
		}
		if current == nil {
			break
		}
		latest, authorized := current()
		if !authorized {
			return false
		}
		if latest <= 0 {
			return true
		}
		if latest == deviceLimit {
			break
		}
		deviceLimit = latest
	}
	if !reclaim {
		return false
	}

	// 名额已满。踢人要先拿到官方客户端的确认，而那是一次对面板的 HTTP 调用，
	// 放不进 Lua，只能拆成「判满 → 取确认 → 原子腾位并登记」三步。判满与腾位
	// 各自原子，所以中途被别的节点占了名额也不会超额登记。
	if !grant.Granted {
		grant = ConsumeReclaimGrant(uid, slot)
	}
	if current != nil {
		var authorized bool
		deviceLimit, authorized = current()
		if !authorized {
			return false
		}
		if deviceLimit <= 0 {
			return true
		}
	}

	policyVersion := g.policyVersion.Load()
	kicked, err := g.eval(evictScript, uid, slot, deviceLimit, grant.TargetSlot, grant.Granted, scope, authorization...).StringSlice()
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "cache service")
		return true
	}
	if len(kicked) == 0 || kicked[0] != "1" {
		if current != nil {
			latest, authorized := current()
			if authorized && (latest != deviceLimit || g.policyVersion.Load() != policyVersion) {
				return g.check(uid, slot, latest, grant, grant.Granted, current, scope, authorization...)
			}
		}
		return false
	}
	for _, kickedSlot := range kicked[1:] {
		g.verified.Delete(fmt.Sprintf("%d|%s", uid, kickedSlot))
		NoteDeviceKick(uid, kickedSlot)
	}
	return true
}

func (g *GlobalDeviceChecker) Verify(uid int, slot string, deviceLimit int, user UserInfo, current ...func() (int, bool)) bool {
	if len(current) > 0 {
		var authorized bool
		deviceLimit, authorized = current[0]()
		if !authorized {
			return false
		}
	}
	if g == nil || deviceLimit <= 0 {
		return true
	}
	if !g.syncPending() {
		return true
	}
	key := fmt.Sprintf("%d|%s", uid, slot)
	if cached, ok := g.verified.Load(key); ok {
		entry := cached.(verifiedSlot)
		if entry.version == user.KickVersion && entry.limit == deviceLimit && time.Now().Before(entry.until) {
			return true
		}
	}
	allowed, err := g.eval(verifyScript, uid, slot, deviceLimit, "", false, user.Scope, user).Int()
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "cache service")
		return true
	}
	if allowed == 1 {
		g.verified.Store(key, verifiedSlot{version: user.KickVersion, limit: deviceLimit, until: time.Now().Add(onlineTouchSec * time.Second)})
	} else if len(current) > 0 {
		latest, authorized := current[0]()
		if !authorized {
			return false
		}
		if latest != deviceLimit {
			return g.Verify(uid, slot, latest, user, current...)
		}
	}
	return allowed == 1
}

// Refresh 续期全局名额中的 名额，闲置过期但尚有空余名额时重新登记；若已被挤出且名额已满
// 则返回 false，禁止踢人抢回。
func (g *GlobalDeviceChecker) Refresh(uid int, slot string, deviceLimit int, authorization ...UserInfo) bool {
	return g.check(uid, slot, deviceLimit, ReclaimGrant{}, false, nil, "", authorization...)
}

func (g *GlobalDeviceChecker) SyncUsers(users *[]api.UserInfo, scope ...string) {
	if g == nil || users == nil {
		return
	}
	g.syncMu.Lock()
	defer g.syncMu.Unlock()
	g.syncUsers(users, scope...)
}

func (g *GlobalDeviceChecker) syncPending() bool {
	if !g.dirty.Load() {
		return true
	}
	if !g.syncMu.TryLock() {
		return false
	}
	defer g.syncMu.Unlock()
	for scope, users := range g.pending {
		g.syncUsers(&users, scope)
		if _, failed := g.pending[scope]; failed {
			return false
		}
	}
	return true
}

func (g *GlobalDeviceChecker) syncUsers(users *[]api.UserInfo, scope ...string) {
	if g.cleanupStop != nil {
		g.cleanupOnce.Do(func() { go g.cleanup() })
	}
	defer g.policyVersion.Add(1)
	g.verified.Range(func(key, value any) bool {
		if time.Now().After(value.(verifiedSlot).until) {
			g.verified.Delete(key)
		}
		return true
	})
	updates := append([]api.UserInfo(nil), (*users)...)
	policies := make(map[int]string, len(updates))
	for _, user := range updates {
		policies[user.ClientID] = fmt.Sprintf("%d|%d", user.DeviceLimit, user.ValidUntil)
	}
	scopeKey := ""
	if len(scope) > 0 {
		scopeKey = scope[0]
	}
	removed := make(map[int]bool)
	scopeRemoved := make(map[int]bool)
	accounts := make(map[int]bool)
	if len(scope) > 0 {
		if g.users == nil {
			g.users = make(map[string]map[int]api.UserInfo)
		}
		if g.users[scope[0]] == nil {
			g.users[scope[0]] = make(map[int]api.UserInfo)
		}
		known := g.users[scope[0]]
		clients := make(map[int]bool)
		for i, user := range updates {
			accounts[user.UID] = true
			clients[user.ClientID] = true
			if user.ClientID != 0 {
				if old, ok := known[user.ClientID]; ok {
					if old.ValidUntil == 0 || user.ValidUntil == 0 {
						user.ValidUntil = 0
					} else {
						user.ValidUntil = max(old.ValidUntil, user.ValidUntil)
					}
				}
				known[user.ClientID] = user
				updates[i] = user
			}
		}
		for _, old := range known {
			if old.ClientID != 0 && !clients[old.ClientID] {
				removed[old.ClientID] = accounts[old.UID]
				scopeRemoved[old.ClientID] = true
				updates = append(updates, old)
			}
		}
	}
	// 限制单次请求大小与脚本工作量。
	const batchSize = 64
	keys := make([]string, 0, 3*batchSize)
	args := make([]any, 4, 4+6*batchSize)
	args[1] = g.expiry
	args[2] = scopeKey
	args[3] = g.clockOffset.Load()
	for i, user := range updates {
		if user.ClientID != 0 {
			slot := OnlineKey(user.ClientID, "")
			key := fmt.Sprintf("UID|%d|client", user.UID)
			kickKey := key + "|kick|" + slot
			keys = append(keys, key, kickKey, kickKey+"|limit|"+scopeKey)
			revoked := 0
			if removed[user.ClientID] {
				revoked = 1
			}
			detached := 0
			if scopeRemoved[user.ClientID] {
				detached = 1
			}
			args = append(args, slot, strconv.FormatUint(user.KickVersion, 10), user.ValidUntil, revoked, policies[user.ClientID], detached)
		}
		if len(keys) == 0 || (len(keys) < 3*batchSize && i < len(updates)-1) {
			continue
		}
		args[0] = time.Now().Unix()
		ctx, cancel := context.WithTimeout(context.Background(), g.timeout)
		_, err := syncKickScript.Run(ctx, g.client, keys, args...).Int()
		cancel()
		if err != nil {
			errors.LogErrorInner(context.Background(), err, "cache service")
			if len(scope) > 0 {
				if g.pending == nil {
					g.pending = make(map[string][]api.UserInfo)
				}
				g.pending[scope[0]] = append([]api.UserInfo(nil), (*users)...)
				g.dirty.Store(true)
			}
			return
		}
		keys = keys[:0]
		args = args[:4]
	}
	if len(scope) > 0 {
		for id, old := range g.users[scope[0]] {
			if removed[id] || (!accounts[old.UID] && old.ValidUntil != 0 && old.ValidUntil+g.expiry <= time.Now().Unix()) {
				delete(g.users[scope[0]], id)
			}
		}
		delete(g.pending, scope[0])
		g.dirty.Store(len(g.pending) > 0)
	}
}

func (g *GlobalDeviceChecker) eval(script *redis.Script, uid int, slot string, deviceLimit int, target string, confirmed bool, scope string, authorization ...UserInfo) *redis.Cmd {
	ctx, cancel := context.WithTimeout(context.Background(), g.timeout)
	defer cancel()

	// 官方客户端与第三方分开记账：两组各自独立使用同一个上限，不互相挤占名额
	redisKey := fmt.Sprintf("UID|%d", uid)
	official := 0
	if IsClientOnlineKey(slot) {
		redisKey += "|client"
		official = 1
		if g.cleanupStop != nil {
			g.cleanupOnce.Do(func() { go g.cleanup() })
		}
	}
	user := UserInfo{}
	if len(authorization) > 0 {
		user = authorization[0]
	}
	// Run 是同步的，返回时结果已落到 Cmd 上，随后取消 context 不影响取值。
	kickKey := redisKey + "|kick|" + slot
	now := time.Now()
	clockOffset := g.clockOffset.Load()
	panelNow := (now.UnixMilli() + clockOffset) / 1000
	return script.Run(ctx, g.client, []string{redisKey, kickKey, kickKey + "|limit|" + scope},
		now.Unix(), g.expiry, slot, deviceLimit, onlineTouchSec, target,
		strconv.FormatUint(user.KickVersion, 10), user.ValidUntil, official, 0, confirmed, now.UnixMilli(), g.timeout.Milliseconds(), scope, panelNow, clockOffset)
}

func (g *GlobalDeviceChecker) SetClockOffset(offset int64) {
	if g != nil {
		g.clockOffset.Store(offset)
	}
}

// 在线 Hash 按面板时间逐项清理；Redis 自身的时钟不能删除整个账本。
func (g *GlobalDeviceChecker) cleanup() {
	defer close(g.cleanupDone)
	ticker := time.NewTicker(time.Duration(g.expiry) * time.Second)
	defer ticker.Stop()
	var cursor uint64
	for {
		select {
		case <-g.cleanupStop:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), g.timeout)
			for ctx.Err() == nil {
				keys, next, err := g.client.Scan(ctx, cursor, "UID|*|client|*", 128).Result()
				if err != nil {
					break
				}
				cursor = next
				for _, key := range keys {
					now := time.Now().UnixMilli() + g.clockOffset.Load()
					ledger := key
					if !strings.Contains(key, "|kick|") {
						ledger = strings.TrimSuffix(key, "|clock")
					}
					if err := cleanupScript.Run(ctx, g.client, []string{ledger, key}, now/1000, g.expiry, "", 0, 0, "", 0, 0, 1, 0, 0, now, 0, "", now/1000, 0).Err(); err != nil {
						break
					}
				}
				if cursor == 0 {
					break
				}
			}
			cancel()
		}
	}
}
