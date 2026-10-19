package traffic

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	bolt "github.com/sagernet/bbolt"
)

var totalsBucket = []byte("totals")
var reportBucket = []byte("report")
var reportKey = []byte("pending")
var cursorKey = []byte("cursor")
var confirmedKey = []byte("confirmed")
var historyBucket = []byte("confirmed_reports")
var initializedKey = []byte("initialized")

type Usage struct {
	UID      int    `json:"user_id"`
	Upload   int64  `json:"u"`
	Download int64  `json:"d"`
	Identity string `json:"traffic_identity,omitempty"`
}

type Report struct {
	ID               string  `json:"report_id"`
	PreviousID       string  `json:"previous_report_id"`
	Data             []Usage `json:"data"`
	Receipt          string  `json:"receipt,omitempty"`
	ReconcileReceipt string  `json:"reconcile_receipt,omitempty"`
}

type Store struct {
	db      *bolt.DB
	mu      sync.Mutex
	queue   []*recordRequest
	writing bool
}

type recordRequest struct {
	Usage
	done chan error
}

func Open(path string) (*Store, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("invalid traffic state directory")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("invalid traffic state file")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		db.Close()
		return nil, err
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(totalsBucket); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(historyBucket); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(deferredBucket); err != nil {
			return err
		}
		metadata, err := tx.CreateBucketIfNotExists(reportBucket)
		if err != nil {
			return err
		}
		if metadata.Get([]byte("ledger")) != nil || metadata.Get([]byte("sequence")) != nil ||
			tx.Bucket([]byte("queued")) != nil || tx.Bucket([]byte("queued_users")) != nil || tx.Bucket([]byte("legacy")) != nil {
			return fmt.Errorf("traffic ledger requires offline conversion with tools/traffic-revert before starting")
		}
		// 兼容面板先升级：旧节点已归档的隔离确认也要在首次升级时收集。
		if metadata.Get([]byte("deferred_indexed")) == nil {
			if err := tx.Bucket(historyBucket).ForEach(func(_, data []byte) error {
				var report Report
				if err := json.Unmarshal(data, &report); err != nil {
					return err
				}
				return rememberDeferred(tx, &report, report.Receipt)
			}); err != nil {
				return err
			}
			return metadata.Put([]byte("deferred_indexed"), []byte{1})
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) NeedsInitialization() (bool, error) {
	var needed bool
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(reportBucket)
		key, _ := tx.Bucket(totalsBucket).Cursor().First()
		needed = bucket.Get(initializedKey) == nil && bucket.Get(confirmedKey) == nil &&
			bucket.Get(reportKey) == nil && key == nil
		return nil
	})
	return needed, err
}

// Initialize 只为尚未开始记流量的空文件建立起点，禁止改写已有待报。
func (s *Store) Initialize(id string) error {
	if id != "" {
		decoded, err := hex.DecodeString(id)
		if err != nil || len(decoded) != 16 || hex.EncodeToString(decoded) != id {
			return fmt.Errorf("invalid initial traffic confirmation")
		}
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(reportBucket)
		key, _ := tx.Bucket(totalsBucket).Cursor().First()
		if bucket.Get(initializedKey) != nil || bucket.Get(confirmedKey) != nil || bucket.Get(reportKey) != nil || key != nil {
			return fmt.Errorf("traffic state is already in use")
		}
		if err := bucket.Put(confirmedKey, []byte(id)); err != nil {
			return err
		}
		return bucket.Put(initializedKey, []byte{1})
	})
}

func (s *Store) Confirmed() (string, error) {
	var id string
	err := s.db.View(func(tx *bolt.Tx) error {
		id = string(tx.Bucket(reportBucket).Get(confirmedKey))
		return nil
	})
	return id, err
}

func (s *Store) RecoverAfter(id string) (*Report, error) {
	var report *Report
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(historyBucket).Get([]byte("after:" + id))
		if data == nil {
			return fmt.Errorf("panel traffic progress differs; required confirmed report is unavailable locally")
		}
		if err := json.Unmarshal(data, &report); err != nil {
			return err
		}
		if err := validateReport(report); err != nil {
			return err
		}
		if report.PreviousID != id || report.Receipt == "" {
			return fmt.Errorf("invalid confirmed traffic history")
		}
		if data := tx.Bucket(deferredBucket).Get([]byte(report.ID)); data != nil {
			var held DeferredReport
			if err := json.Unmarshal(data, &held); err != nil {
				return err
			}
			if len(held.Proofs) != 0 {
				return fmt.Errorf("deferred traffic receipts require reconciliation")
			}
			// 再次恢复只能重放隔离后的处置，不能回到隔离前重新扣量。
			report.Receipt = held.Confirmation
		}
		return nil
	})
	return report, err
}

func (s *Store) Record(uid int, upload, download int64, identity ...string) error {
	if uid <= 0 || upload < 0 || download < 0 || upload > math.MaxInt64-download {
		return fmt.Errorf("invalid traffic record")
	}
	if upload == 0 && download == 0 {
		return nil
	}
	request := &recordRequest{Usage: Usage{UID: uid, Upload: upload, Download: download}, done: make(chan error, 1)}
	if len(identity) > 1 || (len(identity) == 1 && len(identity[0]) > 40) {
		return fmt.Errorf("invalid traffic identity")
	}
	if len(identity) == 1 {
		request.Identity = identity[0]
	}
	s.mu.Lock()
	s.queue = append(s.queue, request)
	if !s.writing {
		s.writing = true
		go s.writeRecords()
	}
	s.mu.Unlock()
	return <-request.done
}

func (s *Store) writeRecords() {
	for {
		s.mu.Lock()
		if len(s.queue) == 0 {
			s.writing = false
			s.mu.Unlock()
			return
		}
		count := min(len(s.queue), 1000)
		batch := s.queue[:count:count]
		s.queue = s.queue[count:]
		if len(s.queue) == 0 {
			s.queue = nil
		}
		s.mu.Unlock()
		results := make([]error, len(batch))
		err := s.db.Update(func(tx *bolt.Tx) error {
			bucket := tx.Bucket(totalsBucket)
			for i, request := range batch {
				key := usageKey(request.UID, request.Identity)
				up, down, err := decodeTotals(bucket.Get(key))
				if err != nil {
					return err
				}
				if request.Upload > math.MaxInt64-up || request.Download > math.MaxInt64-down {
					results[i] = fmt.Errorf("traffic counter overflow")
					continue
				}
				if err := bucket.Put(key, encodeTotals(up+request.Upload, down+request.Download)); err != nil {
					return err
				}
			}
			return nil
		})
		for i, request := range batch {
			if err != nil {
				request.done <- err
			} else {
				request.done <- results[i]
			}
		}
		runtime.Gosched()
	}
}

func (s *Store) Pending() (*Report, error) {
	var report *Report
	err := s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(reportBucket)
		if data := bucket.Get(reportKey); data != nil {
			if err := json.Unmarshal(data, &report); err != nil {
				return fmt.Errorf("invalid pending traffic report: %w", err)
			}
			if err := validateReport(report); err != nil {
				return err
			}
			if report.PreviousID != string(bucket.Get(confirmedKey)) {
				return fmt.Errorf("pending traffic report does not follow confirmation")
			}
			return nil
		}
		var usage []Usage
		var total int64
		cursor := tx.Bucket(totalsBucket).Cursor()
		var key, value []byte
		if last := bucket.Get(cursorKey); last != nil {
			if len(last) < 8 || len(last) > 48 {
				return fmt.Errorf("invalid traffic cursor")
			}
			key, value = cursor.Seek(last)
			if string(key) == string(last) {
				key, value = cursor.Next()
			}
		} else {
			key, value = cursor.First()
		}
		if key == nil {
			key, value = cursor.First()
		}
		first := string(key)
		var lastKey []byte
		seen := make(map[int]bool)
		for key != nil {
			if len(key) < 8 || len(key) > 48 {
				return fmt.Errorf("invalid traffic account key")
			}
			up, down, err := decodeTotals(value)
			if err != nil {
				return err
			}
			if up > math.MaxInt64-down {
				return fmt.Errorf("traffic counter overflow")
			}
			uid := binary.BigEndian.Uint64(key[:8])
			if uid == 0 || uid > uint64(math.MaxInt) {
				return fmt.Errorf("invalid traffic account key")
			}
			// 同一编号的不同身份分批上报，下一批从尚未处理的身份继续。
			if seen[int(uid)] || total > math.MaxInt64-up-down {
				break
			}
			total += up + down
			usage = append(usage, Usage{UID: int(uid), Upload: up, Download: down, Identity: string(key[8:])})
			seen[int(uid)] = true
			lastKey = append(lastKey[:0], key...)
			if len(usage) == 1000 {
				break
			}
			key, value = cursor.Next()
			if key == nil {
				key, value = cursor.First()
			}
			if string(key) == first {
				break
			}
		}
		if len(usage) == 0 {
			return nil
		}
		sort.Slice(usage, func(i, j int) bool { return usage[i].UID < usage[j].UID })
		if err := bucket.Put(cursorKey, lastKey); err != nil {
			return err
		}
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			return err
		}
		report = &Report{ID: hex.EncodeToString(id[:]), PreviousID: string(bucket.Get(confirmedKey)), Data: usage}
		if err := validateReport(report); err != nil {
			return err
		}
		data, err := json.Marshal(report)
		if err != nil {
			return err
		}
		return bucket.Put(reportKey, data)
	})
	return report, err
}

func (s *Store) Confirm(id string, receipt ...string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(reportBucket)
		var report Report
		if err := json.Unmarshal(bucket.Get(reportKey), &report); err != nil || report.ID != id {
			return fmt.Errorf("traffic confirmation does not match pending report")
		}
		if err := validateReport(&report); err != nil {
			return err
		}
		if report.PreviousID != string(bucket.Get(confirmedKey)) {
			return fmt.Errorf("pending traffic report does not follow confirmation")
		}
		if len(receipt) > 0 && receipt[0] != "" {
			if err := rememberDeferred(tx, &report, receipt[0]); err != nil {
				return err
			}
			report.Receipt = receipt[0]
			data, err := json.Marshal(report)
			if err != nil {
				return err
			}
			if err := tx.Bucket(historyBucket).Put([]byte("after:"+report.PreviousID), data); err != nil {
				return err
			}
		}
		totals := tx.Bucket(totalsBucket)
		for _, u := range report.Data {
			key := usageKey(u.UID, u.Identity)
			up, down, err := decodeTotals(totals.Get(key))
			if err != nil || up < u.Upload || down < u.Download {
				return fmt.Errorf("traffic totals do not cover pending report")
			}
			if up == u.Upload && down == u.Download {
				if err := totals.Delete(key); err != nil {
					return err
				}
			} else if err := totals.Put(key, encodeTotals(up-u.Upload, down-u.Download)); err != nil {
				return err
			}
		}
		if err := bucket.Put(confirmedKey, []byte(report.ID)); err != nil {
			return err
		}
		return bucket.Delete(reportKey)
	})
}

func validateReport(report *Report) error {
	if report == nil || report.ReconcileReceipt != "" || len(report.ID) != 32 || len(report.Data) == 0 || len(report.Data) > 1000 {
		return fmt.Errorf("invalid pending traffic report")
	}
	decoded, err := hex.DecodeString(report.ID)
	if err != nil || hex.EncodeToString(decoded) != report.ID {
		return fmt.Errorf("invalid pending traffic report")
	}
	if report.PreviousID != "" {
		decoded, err := hex.DecodeString(report.PreviousID)
		if err != nil || len(decoded) != 16 || hex.EncodeToString(decoded) != report.PreviousID || report.PreviousID == report.ID {
			return fmt.Errorf("invalid previous traffic report")
		}
	}
	lastUID := 0
	var total int64
	for _, u := range report.Data {
		if u.UID <= lastUID || len(u.Identity) > 40 || u.Upload < 0 || u.Download < 0 || (u.Upload == 0 && u.Download == 0) ||
			u.Upload > math.MaxInt64-u.Download || total > math.MaxInt64-u.Upload-u.Download {
			return fmt.Errorf("invalid pending traffic report")
		}
		total += u.Upload + u.Download
		lastUID = u.UID
	}
	return nil
}

func usageKey(uid int, identity string) []byte {
	key := make([]byte, 8+len(identity))
	binary.BigEndian.PutUint64(key[:8], uint64(uid))
	copy(key[8:], identity)
	return key
}

func decodeTotals(data []byte) (int64, int64, error) {
	if data == nil {
		return 0, 0, nil
	}
	if len(data) != 16 {
		return 0, 0, fmt.Errorf("invalid traffic totals")
	}
	up := binary.BigEndian.Uint64(data[:8])
	down := binary.BigEndian.Uint64(data[8:])
	if up > math.MaxInt64 || down > math.MaxInt64 {
		return 0, 0, fmt.Errorf("invalid traffic totals")
	}
	return int64(up), int64(down), nil
}

func encodeTotals(up, down int64) []byte {
	data := make([]byte, 16)
	binary.BigEndian.PutUint64(data[:8], uint64(up))
	binary.BigEndian.PutUint64(data[8:], uint64(down))
	return data
}
