package limiter

import (
	"context"
	"fmt"
	"time"

	"github.com/eko/gocache/lib/v4/cache"
	"github.com/eko/gocache/lib/v4/marshaler"
	"github.com/eko/gocache/lib/v4/store"
	goCacheStore "github.com/eko/gocache/store/go_cache/v4"
	redisStore "github.com/eko/gocache/store/redis/v4"
	goCache "github.com/patrickmn/go-cache"
	"github.com/redis/go-redis/v9"
	"github.com/xtls/xray-core/common/errors"
)

// GlobalDeviceChecker 基于共享 Redis 的跨节点设备限制检查器。
// 缓存 key 按 UID 聚合（"UID|<uid>"），value 为 IP -> 最近活跃时间（unix 秒），
// 所有指向同一 Redis 的节点共同维护一份用户在线 IP 集合。
// 供 Xray 系 limiter 与 Hysteria2 / AnyTLS / TUIC 服务共用。
type GlobalDeviceChecker struct {
	config *GlobalDeviceLimitConfig
	store  *marshaler.Marshaler
	expiry int64 // second
}

// NewGlobalDeviceChecker 未启用全局限制时返回 nil；nil 检查器的 Allow 恒放行。
func NewGlobalDeviceChecker(config *GlobalDeviceLimitConfig) *GlobalDeviceChecker {
	if config == nil || !config.Enable {
		return nil
	}

	expiry := config.Expiry
	if expiry <= 0 {
		// Expiry 未配置时条目会立即过期、限制失效，回退到示例配置默认值
		expiry = 60
	}

	// 本地缓存使用短 TTL，尽快看到其他节点写入 Redis 的在线 IP
	gs := goCacheStore.NewGoCache(goCache.New(time.Duration(onlineTouchSec)*time.Second, 1*time.Minute))

	rs := redisStore.NewRedis(redis.NewClient(
		&redis.Options{
			Network:  config.RedisNetwork,
			Addr:     config.RedisAddr,
			Username: config.RedisUsername,
			Password: config.RedisPassword,
			DB:       config.RedisDB,
		}),
		store.WithExpiration(time.Duration(expiry)*time.Second))

	cacheManager := cache.NewChain[any](
		cache.New[any](gs), // go-cache is priority
		cache.New[any](rs),
	)

	return &GlobalDeviceChecker{
		config: config,
		store:  marshaler.New(cacheManager),
		expiry: int64(expiry),
	}
}

// Allow 判定 uid 的 ip 是否允许在线（全局口径）。
// 已在线 IP 刷新活跃时间并放行；新 IP 在名额未满时登记放行，超限拒绝。
func (g *GlobalDeviceChecker) Allow(uid int, ip string, deviceLimit int) bool {
	if g == nil || deviceLimit <= 0 {
		return true
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(g.config.Timeout)*time.Second)
	defer cancel()

	uniqueKey := fmt.Sprintf("UID|%d", uid)
	now := time.Now().Unix()

	v, err := g.store.Get(ctx, uniqueKey, new(map[string]int64))
	if err != nil {
		if _, ok := err.(*store.NotFound); ok {
			// First time seeing this user
			go g.push(uniqueKey, &map[string]int64{ip: now})
		} else {
			errors.LogErrorInner(context.Background(), err, "cache service")
		}
		return true
	}

	ipMap := v.(*map[string]int64)
	for k, lastSeen := range *ipMap {
		if now-lastSeen > g.expiry {
			delete(*ipMap, k)
		}
	}

	lastSeen, online := (*ipMap)[ip]
	if !online && len(*ipMap) >= deviceLimit {
		return false
	}

	// 新 IP 立即登记；已在线 IP 节流刷新，避免高频写缓存
	if !online || now-lastSeen >= onlineTouchSec {
		(*ipMap)[ip] = now
		go g.push(uniqueKey, ipMap)
	}
	return true
}

func (g *GlobalDeviceChecker) push(uniqueKey string, ipMap *map[string]int64) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(g.config.Timeout)*time.Second)
	defer cancel()

	if err := g.store.Set(ctx, uniqueKey, ipMap); err != nil {
		errors.LogErrorInner(context.Background(), err, "cache service")
	}
}
