package sspanel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/ECYCloud/ECYCloudNode/common/traffic"
)

func trafficDirectory(configured string) string {
	if configured != "" {
		return configured
	}
	if runtime.GOOS == "windows" {
		executable, err := os.Executable()
		if err != nil {
			return ""
		}
		return filepath.Join(filepath.Dir(executable), "traffic")
	}
	return "/var/lib/ECYCloudNode/traffic"
}

func (c *APIClient) trafficPath(host string) string {
	identity := sha256.Sum256([]byte(host + "\n" + strconv.Itoa(c.NodeID)))
	return filepath.Join(c.trafficDir, hex.EncodeToString(identity[:])+".db")
}

// UpdateAPIHost 在启动服务前切换面板下发的地址，两个地址共用同一份流量文件。
func (c *APIClient) UpdateAPIHost(host string) error {
	c.trafficMu.Lock()
	defer c.trafficMu.Unlock()
	if c.trafficDir == "" {
		return fmt.Errorf("traffic state directory unavailable")
	}
	oldPath, newPath := c.trafficPath(c.APIHost), c.trafficPath(host)
	if oldPath != newPath {
		var files [2]os.FileInfo
		for i, path := range []string{oldPath, newPath} {
			info, err := os.Lstat(path)
			if err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("cannot inspect traffic state: %w", err)
			}
			if info != nil && !info.Mode().IsRegular() {
				return fmt.Errorf("invalid traffic state file")
			}
			files[i] = info
		}
		if files[0] != nil && files[1] != nil {
			if !os.SameFile(files[0], files[1]) {
				return fmt.Errorf("panel addresses have separate traffic states; refusing to overwrite either file")
			}
		} else {
			source, target := oldPath, newPath
			if files[0] == nil && files[1] != nil {
				source, target = newPath, oldPath
			} else if files[0] == nil {
				store, err := traffic.Open(source)
				if err != nil {
					return err
				}
				if err := store.Close(); err != nil {
					return err
				}
			}
			// 硬链接保留同一文件与数据库锁，重启或再次改域名也不会复制待报。
			if err := os.Link(source, target); err != nil {
				return fmt.Errorf("cannot retain traffic state when changing panel address: %w", err)
			}
		}
	}
	c.client.SetBaseURL(host)
	c.trafficClient.SetBaseURL(host)
	c.APIHost = host
	return nil
}

func (c *APIClient) PrepareTraffic() error {
	c.trafficMu.Lock()
	defer c.trafficMu.Unlock()
	if c.trafficState == nil {
		if c.trafficDir == "" {
			return fmt.Errorf("traffic state directory unavailable")
		}
		store, err := traffic.Open(c.trafficPath(c.APIHost))
		if err != nil {
			return fmt.Errorf("cannot open traffic state: %w", err)
		}
		fresh, err := store.NeedsInitialization()
		if err == nil && fresh {
			var id string
			id, err = c.trafficProgress()
			if err == nil {
				err = store.Initialize(id)
			}
		}
		if err != nil {
			store.Close()
			return err
		}
		c.trafficState = store
	}
	return nil
}

func (c *APIClient) RecordUserTraffic(uid int, upload, download int64, identity ...string) error {
	c.trafficMu.RLock()
	defer c.trafficMu.RUnlock()
	if c.trafficState == nil {
		return fmt.Errorf("traffic state is not open")
	}
	return c.trafficState.Record(uid, upload, download, identity...)
}

func (c *APIClient) ReportUserTraffic() error {
	c.trafficReportMu.Lock()
	defer c.trafficReportMu.Unlock()
	c.trafficMu.RLock()
	defer c.trafficMu.RUnlock()
	store := c.trafficState
	if store == nil {
		return fmt.Errorf("traffic state is not open")
	}
	report, err := store.Pending()
	if err != nil {
		return err
	}
	confirmed, err := store.Confirmed()
	if err != nil {
		return err
	}
	progress, err := c.trafficProgress()
	if err != nil {
		return err
	}
	for {
		merge, err := store.DeferredMerge()
		if err != nil {
			return err
		}
		if merge == nil {
			break
		}
		receipt, err := c.sendTrafficReport(merge)
		if err != nil {
			return err
		}
		if receipt == merge.Receipt || receipt == merge.ReconcileReceipt {
			return fmt.Errorf("panel did not reconcile deferred traffic receipts; originals retained")
		}
		merge.ReconcileReceipt = ""
		if err := store.RememberDeferred(merge, receipt); err != nil {
			return err
		}
	}
	// 先恢复面板回退后缺少的确认报告，再发送当前待报；补报不再次扣本地计数。
	for count := 0; progress != confirmed && (report == nil || progress != report.ID); count++ {
		if count == 100 {
			return fmt.Errorf("traffic recovery is incomplete; remaining reports retained")
		}
		recovery, err := store.RecoverAfter(progress)
		if err != nil {
			return err
		}
		receipt, err := c.sendTrafficReport(recovery)
		if err != nil {
			return err
		}
		if err := store.RememberDeferred(recovery, receipt); err != nil {
			return err
		}
		progress = recovery.ID
	}
	if report == nil {
		return nil
	}
	receipt, err := c.sendTrafficReport(report)
	if err != nil {
		return err
	}
	return store.Confirm(report.ID, receipt)
}

func (c *APIClient) trafficProgress() (string, error) {
	path := "/mod_mu/users/traffic"
	res, requestErr := c.trafficClient.R().SetQueryParam("node_id", strconv.Itoa(c.NodeID)).
		SetResult(&Response{}).ForceContentType("application/json").Get(path)
	response, err := c.parseResponse(res, path, requestErr)
	if err != nil {
		return "", fmt.Errorf("cannot read panel traffic progress; local traffic retained")
	}
	var progress struct {
		ID      *string `json:"report_id"`
		Receipt string  `json:"receipt"`
	}
	if err := json.Unmarshal(response.Data, &progress); err != nil || progress.ID == nil {
		return "", fmt.Errorf("panel did not return traffic progress")
	}
	if c.trafficState != nil {
		if err := c.trafficState.RememberDeferredConfirmation(*progress.ID, progress.Receipt); err != nil {
			return "", err
		}
	}
	return *progress.ID, nil
}

func (c *APIClient) sendTrafficReport(report *traffic.Report) (string, error) {
	path := "/mod_mu/users/traffic"
	res, requestErr := c.trafficClient.R().SetQueryParam("node_id", strconv.Itoa(c.NodeID)).
		SetBody(report).SetResult(&Response{}).ForceContentType("application/json").Post(path)
	response, err := c.parseResponse(res, path, requestErr)
	if err != nil {
		if res != nil && res.StatusCode() > 0 {
			return "", fmt.Errorf("traffic report was not confirmed (HTTP %d)", res.StatusCode())
		}
		return "", fmt.Errorf("traffic report request failed; pending report retained")
	}
	var confirmation struct {
		ID      string `json:"report_id"`
		Receipt string `json:"receipt"`
	}
	if err := json.Unmarshal(response.Data, &confirmation); err != nil || confirmation.ID != report.ID {
		return "", fmt.Errorf("panel did not confirm the pending traffic report")
	}
	return confirmation.Receipt, nil
}

func (c *APIClient) CloseTraffic() error {
	c.trafficMu.Lock()
	defer c.trafficMu.Unlock()
	if c.trafficState == nil {
		return nil
	}
	err := c.trafficState.Close()
	c.trafficState = nil
	return err
}
