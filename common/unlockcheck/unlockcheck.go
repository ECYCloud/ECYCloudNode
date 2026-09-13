package unlockcheck

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// Global cache for unlock check results (shared across all nodes on the same server)
var (
	globalCacheMutex    sync.RWMutex
	globalCachedResults *UnlockCheckResults
	globalCacheTime     time.Time
	globalCacheHour     int    // The hour when the cache was created
	globalCacheDate     string // The date when the cache was created

	// Check lock for ensuring only one node performs detection
	checkLockMutex sync.Mutex
	isChecking     bool

	// Global node ID registry for multi-node support
	nodeRegistryMutex sync.RWMutex
	registeredNodeIDs []int        // All node IDs that should receive results
	reportedNodeIDs   map[int]bool // Node IDs that have already reported in current hour
	reportedHour      int          // The hour when reportedNodeIDs was last reset
	reportedDate      string       // The date when reportedNodeIDs was last reset
)

// ResetNodeIDs 清空节点注册表。注册表是包级状态，热重载会重新注册当前节点列表；
// 不先清空的话，配置里已删掉的节点仍会被当成共享检测的上报对象。
func ResetNodeIDs() {
	nodeRegistryMutex.Lock()
	defer nodeRegistryMutex.Unlock()

	registeredNodeIDs = nil
}

// RegisterNodeID registers a node ID for unlock check result sharing.
// All registered nodes will receive the same detection results.
func RegisterNodeID(nodeID int) {
	nodeRegistryMutex.Lock()
	defer nodeRegistryMutex.Unlock()

	// Check if already registered
	for _, id := range registeredNodeIDs {
		if id == nodeID {
			return
		}
	}
	registeredNodeIDs = append(registeredNodeIDs, nodeID)
	log.Infof("[UnlockCheck] Registered node %d for shared detection (total: %d nodes)", nodeID, len(registeredNodeIDs))
}

// GetRegisteredNodeIDs returns all registered node IDs
func GetRegisteredNodeIDs() []int {
	nodeRegistryMutex.RLock()
	defer nodeRegistryMutex.RUnlock()

	result := make([]int, len(registeredNodeIDs))
	copy(result, registeredNodeIDs)
	return result
}

// MarkNodeReported marks a node as having reported in the current hour
func MarkNodeReported(nodeID int) {
	nodeRegistryMutex.Lock()
	defer nodeRegistryMutex.Unlock()

	now := time.Now()
	currentHour := now.Hour()
	currentDate := now.Format("2006-01-02")

	// Reset if hour changed
	if reportedHour != currentHour || reportedDate != currentDate {
		reportedNodeIDs = make(map[int]bool)
		reportedHour = currentHour
		reportedDate = currentDate
	}

	if reportedNodeIDs == nil {
		reportedNodeIDs = make(map[int]bool)
	}
	reportedNodeIDs[nodeID] = true
}

// HasNodeReported checks if a node has already reported in the current hour
func HasNodeReported(nodeID int) bool {
	nodeRegistryMutex.RLock()
	defer nodeRegistryMutex.RUnlock()

	now := time.Now()
	currentHour := now.Hour()
	currentDate := now.Format("2006-01-02")

	// If hour changed, no one has reported yet
	if reportedHour != currentHour || reportedDate != currentDate {
		return false
	}

	if reportedNodeIDs == nil {
		return false
	}
	return reportedNodeIDs[nodeID]
}

// GetCachedResults returns cached results if still valid for the current hour, otherwise returns nil
func GetCachedResults() *UnlockCheckResults {
	globalCacheMutex.RLock()
	defer globalCacheMutex.RUnlock()

	if globalCachedResults == nil {
		return nil
	}

	// Cache is valid if it was created in the current hour on the same date
	now := time.Now()
	currentHour := now.Hour()
	currentDate := now.Format("2006-01-02")

	if globalCacheDate == currentDate && globalCacheHour == currentHour {
		return globalCachedResults
	}

	return nil
}

// SetCachedResults stores the results in global cache
func SetCachedResults(results *UnlockCheckResults) {
	globalCacheMutex.Lock()
	defer globalCacheMutex.Unlock()

	now := time.Now()
	globalCachedResults = results
	globalCacheTime = now
	globalCacheHour = now.Hour()
	globalCacheDate = now.Format("2006-01-02")
}

// TryAcquireCheckLock tries to acquire the lock for performing detection
// Returns true if this caller should perform the check, false if another node is already checking
func TryAcquireCheckLock() bool {
	checkLockMutex.Lock()
	defer checkLockMutex.Unlock()

	if isChecking {
		return false
	}
	isChecking = true
	return true
}

// ReleaseCheckLock releases the check lock
func ReleaseCheckLock() {
	checkLockMutex.Lock()
	defer checkLockMutex.Unlock()
	isChecking = false
}

// IsChecking returns whether a check is currently in progress
func IsChecking() bool {
	checkLockMutex.Lock()
	defer checkLockMutex.Unlock()
	return isChecking
}

// UnlockCheckResults represents all unlock check results
type UnlockCheckResults struct {
	YouTubePremium string `json:"YouTube_Premium"`
	Netflix        string `json:"Netflix"`
	DisneyPlus     string `json:"DisneyPlus"`
	HBOMax         string `json:"HBOMax"`
	AmazonPrime    string `json:"AmazonPrime"`
	OpenAI         string `json:"OpenAI"`
	Gemini         string `json:"Gemini"`
	Claude         string `json:"Claude"`
	TikTok         string `json:"TikTok"`
}

// Checker performs unlock checks using embedded csm.sh script
type Checker struct {
	logger *log.Entry
}

// NewChecker creates a new unlock checker
func NewChecker(logger *log.Entry) *Checker {
	return &Checker{
		logger: logger,
	}
}

// RunAllChecks performs all unlock checks by executing embedded csm.sh script
// 脚本执行或输出校验失败时，所有检查返回 Unknown。
func (c *Checker) RunAllChecks() *UnlockCheckResults {
	// Default results (all Unknown)
	defaultResults := &UnlockCheckResults{
		YouTubePremium: "Unknown",
		Netflix:        "Unknown",
		DisneyPlus:     "Unknown",
		HBOMax:         "Unknown",
		AmazonPrime:    "Unknown",
		OpenAI:         "Unknown",
		Gemini:         "Unknown",
		Claude:         "Unknown",
		TikTok:         "Unknown",
	}

	// Execute the embedded script.
	scriptResults := c.runCSMScript()
	if scriptResults != nil {
		c.logger.Info("[UnlockCheck] csm.sh script executed successfully")
		return scriptResults
	}

	// Script failed - return default Unknown results
	c.logger.Error("[UnlockCheck] csm.sh script failed, returning Unknown for all services")
	return defaultResults
}

// runCSMScript 使用标准输入/输出传递脚本和结果，避免并发检测覆盖文件。
func (c *Checker) runCSMScript() *UnlockCheckResults {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	execCmd := exec.CommandContext(ctx, "bash", "-s")
	execCmd.Stdin = strings.NewReader(CSM_SCRIPT)
	execCmd.WaitDelay = 5 * time.Second
	var stderr bytes.Buffer
	execCmd.Stderr = &stderr
	resultData, err := execCmd.Output()
	if err != nil {
		c.logger.Warnf("[UnlockCheck] Script failed: %v; %s", err, stderr.String())
		return nil
	}
	if stderr.Len() > 0 {
		c.logger.Debugf("[UnlockCheck] Probe diagnostics: %s", stderr.String())
	}
	var results UnlockCheckResults
	if err := json.Unmarshal(resultData, &results); err != nil {
		c.logger.Warnf("[UnlockCheck] Invalid result JSON: %v", err)
		return nil
	}
	for _, result := range []string{results.YouTubePremium, results.Netflix, results.DisneyPlus,
		results.HBOMax, results.AmazonPrime, results.OpenAI, results.Gemini, results.Claude, results.TikTok} {
		if result == "" {
			c.logger.Warn("[UnlockCheck] Incomplete script results")
			return nil
		}
	}
	return &results
}

// ToJSON converts results to JSON string
func (r *UnlockCheckResults) ToJSON() string {
	data, err := json.Marshal(r)
	if err != nil {
		return "{}"
	}
	return string(data)
}

// GetCSMScript returns the embedded CSM script content for external use
func GetCSMScript() string {
	return CSM_SCRIPT
}
