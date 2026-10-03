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

type Usage struct {
	UID      int   `json:"user_id"`
	Upload   int64 `json:"u"`
	Download int64 `json:"d"`
}

type Report struct {
	ID   string  `json:"report_id"`
	Data []Usage `json:"data"`
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
		_, err := tx.CreateBucketIfNotExists(reportBucket)
		return err
	}); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Record(uid int, upload, download int64) error {
	if uid <= 0 || upload < 0 || download < 0 {
		return fmt.Errorf("invalid traffic record")
	}
	if upload == 0 && download == 0 {
		return nil
	}
	request := &recordRequest{Usage: Usage{UID: uid, Upload: upload, Download: download}, done: make(chan error, 1)}
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
				var key [8]byte
				binary.BigEndian.PutUint64(key[:], uint64(request.UID))
				up, down, err := decodeTotals(bucket.Get(key[:]))
				if err != nil {
					return err
				}
				if request.Upload > math.MaxInt64-up || request.Download > math.MaxInt64-down {
					results[i] = fmt.Errorf("traffic counter overflow")
					continue
				}
				if err := bucket.Put(key[:], encodeTotals(up+request.Upload, down+request.Download)); err != nil {
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
			return validateReport(report)
		}
		var usage []Usage
		cursor := tx.Bucket(totalsBucket).Cursor()
		var key, value []byte
		if last := bucket.Get(cursorKey); last != nil {
			if len(last) != 8 {
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
		var lastUID int
		for key != nil {
			if len(key) != 8 {
				return fmt.Errorf("invalid traffic account key")
			}
			up, down, err := decodeTotals(value)
			if err != nil {
				return err
			}
			uid := binary.BigEndian.Uint64(key)
			if uid == 0 || uid > uint64(math.MaxInt) {
				return fmt.Errorf("invalid traffic account key")
			}
			usage = append(usage, Usage{UID: int(uid), Upload: up, Download: down})
			lastUID = int(uid)
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
		last := make([]byte, 8)
		binary.BigEndian.PutUint64(last, uint64(lastUID))
		if err := bucket.Put(cursorKey, last); err != nil {
			return err
		}
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			return err
		}
		report = &Report{ID: hex.EncodeToString(id[:]), Data: usage}
		data, err := json.Marshal(report)
		if err != nil {
			return err
		}
		return bucket.Put(reportKey, data)
	})
	return report, err
}

func (s *Store) Confirm(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(reportBucket)
		var report Report
		if err := json.Unmarshal(bucket.Get(reportKey), &report); err != nil || report.ID != id {
			return fmt.Errorf("traffic confirmation does not match pending report")
		}
		if err := validateReport(&report); err != nil {
			return err
		}
		totals := tx.Bucket(totalsBucket)
		for _, u := range report.Data {
			key := make([]byte, 8)
			binary.BigEndian.PutUint64(key, uint64(u.UID))
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
		return bucket.Delete(reportKey)
	})
}

func validateReport(report *Report) error {
	if report == nil || len(report.ID) != 32 || len(report.Data) == 0 || len(report.Data) > 1000 {
		return fmt.Errorf("invalid pending traffic report")
	}
	if _, err := hex.DecodeString(report.ID); err != nil {
		return fmt.Errorf("invalid pending traffic report")
	}
	lastUID := 0
	for _, u := range report.Data {
		if u.UID <= lastUID || u.Upload < 0 || u.Download < 0 || (u.Upload == 0 && u.Download == 0) {
			return fmt.Errorf("invalid pending traffic report")
		}
		lastUID = u.UID
	}
	return nil
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
