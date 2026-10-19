package traffic

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	bolt "github.com/sagernet/bbolt"
)

var deferredBucket = []byte("deferred_reports")

type DeferredEntry struct {
	UID    int    `json:"user_id"`
	Reason string `json:"reason"`
	Scope  string `json:"scope"`
}

// 原报告与原凭据完整保留，Confirmation 只确认已入账/待核对的区分。
type DeferredReport struct {
	Report       Report          `json:"report"`
	Confirmation string          `json:"confirmation"`
	Entries      []DeferredEntry `json:"entries"`
	Proofs       []string        `json:"proofs,omitempty"`
	Evidence     []string        `json:"evidence,omitempty"`
}

type deferredConfirmation struct {
	ID         string
	PreviousID string
	Hash       string
	Entries    []DeferredEntry
	Metadata   string
}

func readDeferredConfirmation(receipt string) (*deferredConfirmation, error) {
	body, _, ok := strings.Cut(receipt, ".")
	if !ok {
		return nil, nil
	}
	data, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, nil
	}
	var fields []json.RawMessage
	if json.Unmarshal(data, &fields) != nil || len(fields) < 5 || string(fields[4]) != "4" {
		return nil, nil
	}
	if len(fields) != 11 {
		return nil, fmt.Errorf("invalid deferred traffic confirmation")
	}
	var ack deferredConfirmation
	metadata, err := json.Marshal(fields[5:10])
	if err != nil {
		return nil, err
	}
	ack.Metadata = string(metadata)
	for _, field := range []struct {
		data   json.RawMessage
		target any
	}{
		{fields[1], &ack.ID}, {fields[2], &ack.PreviousID}, {fields[3], &ack.Hash}, {fields[10], &ack.Entries},
	} {
		if err := json.Unmarshal(field.data, field.target); err != nil {
			return nil, err
		}
	}
	if len(ack.Entries) == 0 || len(ack.Entries) > 1000 {
		return nil, fmt.Errorf("invalid deferred traffic entries")
	}
	return &ack, nil
}

func rememberDeferred(tx *bolt.Tx, report *Report, receipt string) error {
	ack, err := readDeferredConfirmation(receipt)
	if err != nil || ack == nil {
		return err
	}
	if err := validateReport(report); err != nil {
		return err
	}
	data, err := json.Marshal(report.Data)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(data)
	if ack.ID != report.ID || ack.PreviousID != report.PreviousID || ack.Hash != hex.EncodeToString(hash[:]) {
		return fmt.Errorf("deferred confirmation does not match original report")
	}
	users := make(map[int]bool, len(report.Data))
	for _, u := range report.Data {
		users[u.UID] = true
	}
	for _, entry := range ack.Entries {
		if !users[entry.UID] {
			return fmt.Errorf("deferred confirmation contains an unknown or duplicate user")
		}
		switch entry.Reason {
		case "missing_identity", "identity_mismatch", "user_missing", "reset_boundary_ambiguous", "receipt_conflict":
		default:
			return fmt.Errorf("invalid deferred traffic reason")
		}
		delete(users, entry.UID)
		if entry.Scope != "user" && entry.Scope != "node" && entry.Scope != "both" {
			return fmt.Errorf("invalid deferred traffic scope")
		}
	}
	original := *report
	confirmation := receipt
	entries := ack.Entries
	var proofs []string
	evidence := []string{receipt}
	if data := tx.Bucket(deferredBucket).Get([]byte(report.ID)); data != nil {
		var held DeferredReport
		if err := json.Unmarshal(data, &held); err != nil {
			return err
		}
		original = held.Report
		evidence = append([]string(nil), held.Evidence...)
		found := false
		for _, value := range evidence {
			found = found || value == receipt
		}
		if !found {
			evidence = append(evidence, receipt)
		}
		// 不相包含的旧确认都要保留，交由面板验证签名并合并，节点不自行签发。
		scopes := map[string]int{"user": 1, "node": 2, "both": 3}
		union := make(map[int]DeferredEntry)
		for _, entry := range held.Entries {
			union[entry.UID] = entry
		}
		for _, entry := range ack.Entries {
			if previous, ok := union[entry.UID]; ok {
				mask := scopes[previous.Scope] | scopes[entry.Scope]
				entry.Scope = map[int]string{1: "user", 2: "node", 3: "both"}[mask]
			}
			union[entry.UID] = entry
		}
		covers := func(values, required []DeferredEntry) bool {
			available := make(map[int]int)
			for _, entry := range values {
				available[entry.UID] = scopes[entry.Scope]
			}
			for _, entry := range required {
				if available[entry.UID]&scopes[entry.Scope] != scopes[entry.Scope] {
					return false
				}
			}
			return true
		}
		old, err := readDeferredConfirmation(held.Confirmation)
		if err != nil || old == nil {
			return fmt.Errorf("invalid retained traffic confirmation")
		}
		conflict := func(values []DeferredEntry) bool {
			if len(values) != len(report.Data) {
				return false
			}
			for _, entry := range values {
				if entry.Reason != "receipt_conflict" || entry.Scope != "both" {
					return false
				}
			}
			return true
		}
		if conflict(old.Entries) {
			confirmation = held.Confirmation
			entries = held.Entries
		} else if conflict(ack.Entries) || ack.Metadata == old.Metadata && covers(ack.Entries, old.Entries) {
			for _, proof := range held.Proofs {
				other, err := readDeferredConfirmation(proof)
				if err != nil || other == nil {
					return fmt.Errorf("invalid retained traffic proof")
				}
				if !conflict(ack.Entries) && (ack.Metadata != other.Metadata || !covers(ack.Entries, other.Entries)) {
					proofs = append(proofs, proof)
				}
			}
		} else {
			confirmation = held.Confirmation
			proofs = append(proofs, held.Proofs...)
			if ack.Metadata != old.Metadata || !covers(old.Entries, ack.Entries) {
				found := confirmation == receipt
				for _, proof := range proofs {
					found = found || proof == receipt
				}
				if !found {
					proofs = append(proofs, receipt)
				}
			}
		}
		if !conflict(old.Entries) {
			entries = nil
			for _, usage := range report.Data {
				if entry, ok := union[usage.UID]; ok {
					entries = append(entries, entry)
				}
			}
		}
	}
	if original.Receipt == "" {
		original.Receipt = receipt
	}
	data, err = json.Marshal(DeferredReport{Report: original, Confirmation: confirmation, Entries: entries, Proofs: proofs, Evidence: evidence})
	if err != nil {
		return err
	}
	return tx.Bucket(deferredBucket).Put([]byte(report.ID), data)
}

// 恢复历史时只留存待核对项，不再次消费已确认的本地计数。
func (s *Store) RememberDeferred(report *Report, receipt string) error {
	return s.db.Update(func(tx *bolt.Tx) error { return rememberDeferred(tx, report, receipt) })
}

// 恢复响应丢失后，先从面板最后的签名重建隔离记录，再推进后续报告。
func (s *Store) RememberDeferredConfirmation(id, receipt string) error {
	ack, err := readDeferredConfirmation(receipt)
	if err != nil || ack == nil {
		return err
	}
	if ack.ID != id {
		return fmt.Errorf("traffic progress does not match deferred confirmation")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		data := tx.Bucket(historyBucket).Get([]byte("after:" + ack.PreviousID))
		// 待报由 Confirm 原子处理；新建空文件也没有可重建的历史正文。
		if data == nil {
			return nil
		}
		var report Report
		if err := json.Unmarshal(data, &report); err != nil {
			return err
		}
		return rememberDeferred(tx, &report, receipt)
	})
}

func (s *Store) DeferredReports() ([]DeferredReport, error) {
	var reports []DeferredReport
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(deferredBucket).ForEach(func(_, value []byte) error {
			var report DeferredReport
			if err := json.Unmarshal(value, &report); err != nil {
				return err
			}
			reports = append(reports, report)
			return nil
		})
	})
	return reports, err
}

func (s *Store) DeferredMerge() (*Report, error) {
	var report *Report
	err := s.db.View(func(tx *bolt.Tx) error {
		cursor := tx.Bucket(deferredBucket).Cursor()
		for _, value := cursor.First(); value != nil; _, value = cursor.Next() {
			var held DeferredReport
			if err := json.Unmarshal(value, &held); err != nil {
				return err
			}
			if len(held.Proofs) != 0 {
				copy := held.Report
				copy.Receipt = held.Confirmation
				copy.ReconcileReceipt = held.Proofs[0]
				report = &copy
				break
			}
		}
		return nil
	})
	return report, err
}
