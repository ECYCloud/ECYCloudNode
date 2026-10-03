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

func (c *APIClient) PrepareTraffic() error {
	c.trafficMu.Lock()
	defer c.trafficMu.Unlock()
	if c.trafficState == nil {
		if c.trafficDir == "" {
			return fmt.Errorf("traffic state directory unavailable")
		}
		path := fmt.Sprintf("/mod_mu/nodes/%d/info", c.NodeID)
		res, requestErr := c.client.R().SetResult(&Response{}).ForceContentType("application/json").Get(path)
		response, err := c.parseResponse(res, path, requestErr)
		if err != nil {
			return fmt.Errorf("cannot verify panel traffic report protocol")
		}
		var protocol struct {
			Version int `json:"traffic_report_version"`
		}
		if err := json.Unmarshal(response.Data, &protocol); err != nil || protocol.Version != 1 {
			return fmt.Errorf("panel does not support idempotent traffic reports; update the panel before starting this node")
		}
		identity := sha256.Sum256([]byte(c.APIHost + "\n" + strconv.Itoa(c.NodeID)))
		store, err := traffic.Open(filepath.Join(c.trafficDir, hex.EncodeToString(identity[:])+".db"))
		if err != nil {
			return fmt.Errorf("cannot open traffic state: %w", err)
		}
		c.trafficState = store
	}
	return nil
}

func (c *APIClient) RecordUserTraffic(uid int, upload, download int64) error {
	c.trafficMu.RLock()
	defer c.trafficMu.RUnlock()
	if c.trafficState == nil {
		return fmt.Errorf("traffic state is not open")
	}
	return c.trafficState.Record(uid, upload, download)
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
	if err != nil || report == nil {
		return err
	}
	path := "/mod_mu/users/traffic"
	res, requestErr := c.trafficClient.R().SetQueryParam("node_id", strconv.Itoa(c.NodeID)).
		SetBody(report).SetResult(&Response{}).ForceContentType("application/json").Post(path)
	response, err := c.parseResponse(res, path, requestErr)
	if err != nil {
		if res != nil && res.StatusCode() > 0 {
			return fmt.Errorf("traffic report was not confirmed (HTTP %d)", res.StatusCode())
		}
		return fmt.Errorf("traffic report request failed; pending report retained")
	}
	var confirmation struct {
		ID string `json:"report_id"`
	}
	if err := json.Unmarshal(response.Data, &confirmation); err != nil || confirmation.ID != report.ID {
		return fmt.Errorf("panel did not confirm the pending traffic report")
	}
	return store.Confirm(report.ID)
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
