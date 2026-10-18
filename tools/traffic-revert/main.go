// 一次性转换已部署的流量账本；不参与节点运行。
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/ECYCloud/ECYCloudNode/common/traffic"
	bolt "github.com/sagernet/bbolt"
)

type checkpoint struct {
	NodeID int    `json:"node_id"`
	ID     string `json:"last_report_id"`
	Hash   string `json:"last_report_hash"`
}

type amounts struct{ Up, Down int64 }
type conversion struct {
	Totals  map[uint64]amounts
	Pending *traffic.Report
	Old     bool
}

func main() {
	state := flag.String("state", "", "已停止节点的当前 .db 账本完整路径")
	host := flag.String("api-host", "", "节点配置中的完整 APIHost，必须完全一致")
	node := flag.Int("node-id", 0, "节点 ID")
	file := flag.String("checkpoint-file", "", "维护期间从对应面板数据库导出的 JSON")
	apply := flag.Bool("apply", false, "先备份，再原子转换；默认只检查")
	flag.Parse()
	if err := run(*state, *host, *node, *file, *apply); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(path, host string, node int, file string, apply bool) error {
	if path == "" || host == "" || node <= 0 || file == "" {
		return fmt.Errorf("必须提供 state、api-host、node-id、checkpoint-file")
	}
	identity := sha256.Sum256([]byte(host + "\n" + strconv.Itoa(node)))
	if filepath.Base(path) != hex.EncodeToString(identity[:])+".db" {
		return fmt.Errorf("账本文件名与 APIHost、节点 ID 不一致")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	var export struct {
		Nodes []checkpoint `json:"nodes"`
	}
	if err := json.Unmarshal(data, &export); err != nil {
		return err
	}
	var cp checkpoint
	found := false
	for _, item := range export.Nodes {
		if item.NodeID == node {
			if found {
				return fmt.Errorf("导出文件含重复节点 ID")
			}
			cp, found = item, true
		}
	}
	if !found {
		return fmt.Errorf("导出文件未包含此节点；禁止猜测确认进度")
	}
	backup, plan, err := convert(path, cp, apply)
	if err != nil {
		return err
	}
	if plan.Old {
		fmt.Println("账本已是原格式，未修改")
		return nil
	}
	fmt.Printf("核对通过：保留 %d 个账户的未确认流量；", len(plan.Totals))
	if !apply {
		fmt.Println("仅检查，未修改。停服期间使用相同参数加 --apply 执行。")
		return nil
	}
	fmt.Printf("转换完成，备份：%s\n", backup)
	return nil
}

func sequence(id string) ([]byte, error) {
	if len(id) != 35 || (id[:3] != "v2:" && id[:3] != "v3:") {
		return nil, fmt.Errorf("无效确认编号")
	}
	value, err := hex.DecodeString(id[3:])
	if err != nil || hex.EncodeToString(value) != id[3:] {
		return nil, fmt.Errorf("无效确认编号")
	}
	return value, nil
}

func readAmounts(data []byte) (amounts, error) {
	if len(data) != 16 {
		return amounts{}, fmt.Errorf("无效流量计数")
	}
	u, d := binary.BigEndian.Uint64(data[:8]), binary.BigEndian.Uint64(data[8:])
	if u > math.MaxInt64 || d > math.MaxInt64 || u+d == 0 {
		return amounts{}, fmt.Errorf("无效流量计数")
	}
	return amounts{int64(u), int64(d)}, nil
}

func account(key []byte) (uint64, error) {
	if len(key) != 8 {
		return 0, fmt.Errorf("无效账户编号")
	}
	id := binary.BigEndian.Uint64(key)
	if id == 0 || id > uint64(math.MaxInt) {
		return 0, fmt.Errorf("无效账户编号")
	}
	return id, nil
}

func load(bucket *bolt.Bucket) (map[uint64]amounts, error) {
	if bucket == nil {
		return nil, fmt.Errorf("账本缺少数据分区")
	}
	result := make(map[uint64]amounts)
	err := bucket.ForEach(func(key, value []byte) error {
		id, err := account(key)
		if err != nil {
			return err
		}
		count, err := readAmounts(value)
		if err != nil {
			return err
		}
		result[id] = count
		return nil
	})
	return result, err
}

func add(target map[uint64]amounts, id uint64, value amounts) error {
	old := target[id]
	if old.Up > math.MaxInt64-value.Up || old.Down > math.MaxInt64-value.Down {
		return fmt.Errorf("账本合计溢出")
	}
	target[id] = amounts{old.Up + value.Up, old.Down + value.Down}
	return nil
}

func subtract(target map[uint64]amounts, id uint64, value amounts) error {
	old := target[id]
	if old.Up < value.Up || old.Down < value.Down {
		return fmt.Errorf("账本不足以核销确认流量")
	}
	if old == value {
		delete(target, id)
	} else {
		target[id] = amounts{old.Up - value.Up, old.Down - value.Down}
	}
	return nil
}

func readReport(data []byte) (*traffic.Report, error) {
	if data == nil {
		return nil, nil
	}
	var r traffic.Report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	id := r.ID
	if len(id) == 35 {
		if _, err := sequence(id); err != nil {
			return nil, err
		}
		id = id[3:]
	}
	decoded, err := hex.DecodeString(id)
	if len(id) != 32 || err != nil || hex.EncodeToString(decoded) != id || len(r.Data) == 0 || len(r.Data) > 1000 {
		return nil, fmt.Errorf("无效待报数据")
	}
	last, total := 0, int64(0)
	for _, u := range r.Data {
		if u.UID <= last || u.Upload < 0 || u.Download < 0 || u.Upload > math.MaxInt64-u.Download || u.Upload+u.Download == 0 || total > math.MaxInt64-u.Upload-u.Download {
			return nil, fmt.Errorf("无效待报流量")
		}
		last, total = u.UID, total+u.Upload+u.Download
	}
	return &r, nil
}

func prepare(tx *bolt.Tx, cp checkpoint) (*conversion, error) {
	var progress []byte
	if cp.ID != "" {
		var err error
		progress, err = sequence(cp.ID)
		if err != nil {
			return nil, err
		}
		hash, err := hex.DecodeString(cp.Hash)
		if err != nil || len(hash) != 32 || hex.EncodeToString(hash) != cp.Hash {
			return nil, fmt.Errorf("面板确认摘要缺失或无效")
		}
	} else if cp.Hash != "" {
		return nil, fmt.Errorf("面板确认编号与摘要矛盾")
	}
	totals, err := load(tx.Bucket([]byte("totals")))
	if err != nil {
		return nil, err
	}
	meta := tx.Bucket([]byte("report"))
	if meta == nil {
		return nil, fmt.Errorf("账本缺少报告分区")
	}
	pending, err := readReport(meta.Get([]byte("pending")))
	if err != nil {
		return nil, err
	}
	plan := &conversion{Totals: totals, Pending: pending}
	if meta.Get([]byte("ledger")) == nil {
		if meta.Get([]byte("sequence")) != nil || tx.Bucket([]byte("legacy")) != nil || tx.Bucket([]byte("queued")) != nil || tx.Bucket([]byte("queued_users")) != nil || (pending != nil && len(pending.ID) != 32) {
			return nil, fmt.Errorf("账本格式不完整，拒绝转换")
		}
		// 原格式重试必须保持原编号，继续依赖面板已有确认记录。
		if progress != nil {
			return nil, fmt.Errorf("账本已是原格式，但面板仍有新版进度；请核对首次转换结果或当前账本来源，拒绝再次转换")
		}
		plan.Old = true
		return plan, nil
	}
	if !bytes.Equal(meta.Get([]byte("ledger")), []byte{3}) {
		return nil, fmt.Errorf("不支持的账本格式")
	}
	local := meta.Get([]byte("sequence"))
	if (local != nil && len(local) != 16) || (progress != nil && (local == nil || bytes.Compare(local, progress) < 0)) {
		return nil, fmt.Errorf("账本早于面板确认进度；请恢复当前账本，禁止使用旧备份")
	}
	legacy, err := load(tx.Bucket([]byte("legacy")))
	if err != nil {
		return nil, err
	}
	queued, users := tx.Bucket([]byte("queued")), tx.Bucket([]byte("queued_users"))
	if queued == nil || users == nil {
		return nil, fmt.Errorf("账本缺少队列分区")
	}
	components := make(map[uint64]amounts)
	for id, value := range legacy {
		components[id] = value
	}
	entries := make(map[string]struct {
		ID    uint64
		Value amounts
	})
	err = queued.ForEach(func(key, value []byte) error {
		if len(key) != 16 || len(value) != 24 || local == nil || bytes.Compare(key, local) > 0 || !bytes.Equal(users.Get(value[:8]), key) {
			return fmt.Errorf("队列编号或账户索引异常")
		}
		id, err := account(value[:8])
		if err != nil {
			return err
		}
		count, err := readAmounts(value[8:])
		if err != nil {
			return err
		}
		if err := add(components, id, count); err != nil {
			return err
		}
		entries[string(key)] = struct {
			ID    uint64
			Value amounts
		}{id, count}
		return nil
	})
	if err != nil {
		return nil, err
	}
	err = users.ForEach(func(key, value []byte) error {
		id, err := account(key)
		if err != nil {
			return err
		}
		entry, ok := entries[string(value)]
		if !ok || entry.ID != id {
			return fmt.Errorf("队列账户索引异常")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if pending != nil {
		if strings.HasPrefix(cp.ID, "v2:") && (len(pending.ID) == 32 || (strings.HasPrefix(pending.ID, "v2:") && pending.ID < cp.ID)) {
			return nil, fmt.Errorf("旧累计账本早于面板进度，无法判定额外累计值；请恢复当前账本")
		}
		if strings.HasPrefix(pending.ID, "v3:") && len(legacy) != 0 {
			return nil, fmt.Errorf("新版待报与旧累计值同时存在，账本状态异常")
		}
		if len(pending.ID) == 35 {
			seq, _ := sequence(pending.ID)
			if local == nil || bytes.Compare(seq, local) > 0 {
				return nil, fmt.Errorf("待报编号超过本地进度")
			}
			if strings.HasPrefix(cp.ID, "v2:") && strings.HasPrefix(pending.ID, "v3:") && bytes.Compare(seq, progress) <= 0 {
				return nil, fmt.Errorf("待报编号与协议切换顺序矛盾")
			}
		}
		for _, u := range pending.Data {
			value := amounts{u.Upload, u.Download}
			if strings.HasPrefix(pending.ID, "v3:") {
				if err := add(components, uint64(u.UID), value); err != nil {
					return nil, err
				}
			} else if legacy[uint64(u.UID)].Up < value.Up || legacy[uint64(u.UID)].Down < value.Down {
				return nil, fmt.Errorf("旧累计值不覆盖待报数据")
			}
		}
		if cp.ID == pending.ID {
			data, _ := json.Marshal(pending.Data)
			hash := sha256.Sum256(data)
			if hex.EncodeToString(hash[:]) != cp.Hash {
				return nil, fmt.Errorf("面板确认摘要与本地待报内容不一致")
			}
		}
	}
	if !reflect.DeepEqual(components, totals) {
		return nil, fmt.Errorf("累计值与队列、待报明细不一致；未修改账本")
	}
	if strings.HasPrefix(cp.ID, "v3:") {
		for id, value := range legacy {
			if err := subtract(totals, id, value); err != nil {
				return nil, err
			}
		}
		for seq, entry := range entries {
			if bytes.Compare([]byte(seq), progress) <= 0 {
				if err := subtract(totals, entry.ID, entry.Value); err != nil {
					return nil, err
				}
			}
		}
	}
	if pending != nil {
		billed := strings.HasPrefix(cp.ID, "v3:") && !strings.HasPrefix(pending.ID, "v3:")
		if len(pending.ID) == 35 && cp.ID != "" && pending.ID[:3] == cp.ID[:3] && pending.ID <= cp.ID {
			billed = true
			for _, u := range pending.Data {
				if err := subtract(totals, uint64(u.UID), amounts{u.Upload, u.Download}); err != nil {
					return nil, err
				}
			}
		}
		if billed {
			plan.Pending = nil
		} else if len(pending.ID) == 35 {
			var id [16]byte
			if _, err := rand.Read(id[:]); err != nil {
				return nil, err
			}
			plan.Pending.ID = hex.EncodeToString(id[:])
		}
	}
	remaining := make(map[uint64]amounts, len(totals))
	for id, value := range totals {
		remaining[id] = value
	}
	if plan.Pending != nil {
		for _, u := range plan.Pending.Data {
			if err := subtract(remaining, uint64(u.UID), amounts{u.Upload, u.Download}); err != nil {
				return nil, err
			}
		}
	}
	for _, value := range remaining {
		if value.Up > math.MaxInt64-value.Down {
			return nil, fmt.Errorf("未确认累计量超过原格式范围，拒绝转换")
		}
	}
	return plan, nil
}

func convert(path string, cp checkpoint, apply bool) (string, *conversion, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", nil, err
	}
	if !info.Mode().IsRegular() {
		return "", nil, fmt.Errorf("账本必须是已有普通文件")
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second, ReadOnly: !apply})
	if err != nil {
		return "", nil, fmt.Errorf("无法独占账本；请先停止节点：%w", err)
	}
	defer db.Close()
	var plan *conversion
	err = db.View(func(tx *bolt.Tx) error { var e error; plan, e = prepare(tx, cp); return e })
	if err != nil || !apply || plan.Old {
		return "", plan, err
	}
	backup := path + ".before-revert-" + time.Now().UTC().Format("20060102T150405.000000000Z")
	output, err := os.OpenFile(backup, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", nil, fmt.Errorf("无法创建独立备份，未转换：%w", err)
	}
	err = db.View(func(tx *bolt.Tx) error { _, e := tx.WriteTo(output); return e })
	if err == nil {
		err = output.Sync()
	}
	closeErr := output.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(backup)
	}
	if err != nil {
		return "", nil, fmt.Errorf("备份失败，未转换：%w", err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		if err := tx.DeleteBucket([]byte("totals")); err != nil {
			return err
		}
		bucket, err := tx.CreateBucket([]byte("totals"))
		if err != nil {
			return err
		}
		for id, value := range plan.Totals {
			var key [8]byte
			var data [16]byte
			binary.BigEndian.PutUint64(key[:], id)
			binary.BigEndian.PutUint64(data[:8], uint64(value.Up))
			binary.BigEndian.PutUint64(data[8:], uint64(value.Down))
			if err := bucket.Put(key[:], data[:]); err != nil {
				return err
			}
		}
		meta := tx.Bucket([]byte("report"))
		if plan.Pending == nil {
			if err := meta.Delete([]byte("pending")); err != nil {
				return err
			}
		} else {
			data, err := json.Marshal(plan.Pending)
			if err != nil {
				return err
			}
			if err := meta.Put([]byte("pending"), data); err != nil {
				return err
			}
		}
		for _, key := range []string{"sequence", "ledger", "cursor"} {
			if err := meta.Delete([]byte(key)); err != nil {
				return err
			}
		}
		for _, name := range []string{"queued", "queued_users", "legacy"} {
			if err := tx.DeleteBucket([]byte(name)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return backup, nil, fmt.Errorf("转换失败，请保留原文件与备份并核对状态；备份：%s：%w", backup, err)
	}
	return backup, plan, nil
}
