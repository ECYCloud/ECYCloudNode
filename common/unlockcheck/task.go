package unlockcheck

import (
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/task"

	"github.com/ECYCloud/ECYCloudNode/api"
)

// NewTask 为各协议复用同一套检测调度和共享上报流程。
func NewTask(apiClient api.API, nodeID int, logger *log.Entry) *task.Periodic {
	checker := NewChecker(logger)
	var mutex sync.Mutex
	logger.Printf("Unlock check task initialized for node %d (config will be fetched from panel)", nodeID)

	return &task.Periodic{
		Interval: time.Minute,
		Execute: func() error {
			mutex.Lock()
			defer mutex.Unlock()

			if HasNodeReported(nodeID) {
				return nil
			}

			config, err := apiClient.GetUnlockCheckConfig()
			if err != nil {
				logger.Printf("[UnlockCheck] Node %d: Failed to get unlock check config: %v", nodeID, err)
				return nil
			}
			if !config.Enabled || config.CheckInterval <= 0 {
				return nil
			}

			now := time.Now()
			currentHour := now.Hour()
			if currentHour%config.CheckInterval != 0 {
				return nil
			}

			if !TryAcquireCheckLock() {
				logger.Printf("[UnlockCheck] Node %d: Another node is performing check, skipping", nodeID)
				return nil
			}
			defer ReleaseCheckLock()

			logger.Printf("[UnlockCheck] Node %d: Performing check at %02d:%02d (interval: %d hours)", nodeID, currentHour, now.Minute(), config.CheckInterval)
			results := checker.RunAllChecks()
			SetCachedResults(results)
			resultJSON := results.ToJSON()
			logger.Printf("[UnlockCheck] Node %d: Results: %s", nodeID, resultJSON)

			allNodeIDs := GetRegisteredNodeIDs()
			logger.Printf("[UnlockCheck] Node %d: Reporting results for %d nodes: %v", nodeID, len(allNodeIDs), allNodeIDs)
			for _, targetNodeID := range allNodeIDs {
				if err := apiClient.ReportUnlockCheckResultForNode(targetNodeID, resultJSON); err != nil {
					logger.Printf("[UnlockCheck] Node %d: Failed to report for node %d: %v", nodeID, targetNodeID, err)
				} else {
					logger.Printf("[UnlockCheck] Node %d: Reported successfully for node %d", nodeID, targetNodeID)
					MarkNodeReported(targetNodeID)
				}
			}
			return nil
		},
	}
}
