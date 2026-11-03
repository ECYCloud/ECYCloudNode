// Package unlockcheck provides streaming unlock detection functionality.
// It checks various streaming services (Netflix, YouTube Premium, Disney+, etc.)
// and reports the results to the panel.
// Detection logic is 100% based on csm.sh script from:
// https://github.com/ECYCloud/check-stream-media
// The script is embedded locally and executed without remote download.
// NO FALLBACK - only uses the embedded csm.sh script for 100% accuracy.
package unlockcheck

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	registeredNodes   []reportTarget        // All nodes that should receive results
	reportedNodes     map[reportTarget]bool // Nodes that have already reported in current hour
	reportedHour      int                   // The hour when reportedNodes was last reset
	reportedDate      string                // The date when reportedNodes was last reset
)

// reportTarget 按面板地址加 NodeID 区分节点：多面板部署时不同面板的同号节点是不同节点，
// 检测结果只能经各自面板的客户端上报。
type reportTarget struct {
	host string
	id   int
}

func newReportTarget(host string, nodeID int) reportTarget {
	return reportTarget{host: strings.TrimRight(strings.TrimSpace(host), "/"), id: nodeID}
}

// ResetNodeIDs 清空节点注册表。注册表是包级状态，热重载会重新注册当前节点列表；
// 不先清空的话，配置里已删掉的节点仍会被当成共享检测的上报对象。
func ResetNodeIDs() {
	nodeRegistryMutex.Lock()
	defer nodeRegistryMutex.Unlock()

	registeredNodes = nil
}

// RegisterNodeID registers a node of the panel at host for unlock check result sharing.
// All registered nodes of the same panel will receive the same detection results.
func RegisterNodeID(host string, nodeID int) {
	if nodeID <= 0 {
		return
	}
	nodeRegistryMutex.Lock()
	defer nodeRegistryMutex.Unlock()

	target := newReportTarget(host, nodeID)
	// Check if already registered
	for _, registered := range registeredNodes {
		if registered == target {
			return
		}
	}
	registeredNodes = append(registeredNodes, target)
	log.Infof("[UnlockCheck] Registered node %d for shared detection (total: %d nodes)", nodeID, len(registeredNodes))
}

// GetRegisteredNodeIDs returns the registered node IDs of the panel at host
func GetRegisteredNodeIDs(host string) []int {
	nodeRegistryMutex.RLock()
	defer nodeRegistryMutex.RUnlock()

	panel := newReportTarget(host, 0).host
	var result []int
	for _, registered := range registeredNodes {
		if registered.host == panel {
			result = append(result, registered.id)
		}
	}
	return result
}

// MarkNodeReported marks a node as having reported in the current hour
func MarkNodeReported(host string, nodeID int) {
	nodeRegistryMutex.Lock()
	defer nodeRegistryMutex.Unlock()

	now := time.Now()
	currentHour := now.Hour()
	currentDate := now.Format("2006-01-02")

	// Reset if hour changed
	if reportedHour != currentHour || reportedDate != currentDate {
		reportedNodes = make(map[reportTarget]bool)
		reportedHour = currentHour
		reportedDate = currentDate
	}

	if reportedNodes == nil {
		reportedNodes = make(map[reportTarget]bool)
	}
	reportedNodes[newReportTarget(host, nodeID)] = true
}

// HasNodeReported checks if a node has already reported in the current hour
func HasNodeReported(host string, nodeID int) bool {
	nodeRegistryMutex.RLock()
	defer nodeRegistryMutex.RUnlock()

	now := time.Now()
	currentHour := now.Hour()
	currentDate := now.Format("2006-01-02")

	// If hour changed, no one has reported yet
	if reportedHour != currentHour || reportedDate != currentDate {
		return false
	}

	if reportedNodes == nil {
		return false
	}
	return reportedNodes[newReportTarget(host, nodeID)]
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
// This ensures 100% consistency with the csm.sh detection logic
// NO FALLBACK - if script fails, returns Unknown for all services
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

	// Execute embedded csm.sh script (100% accurate detection)
	scriptResults := c.runCSMScript()
	if scriptResults != nil {
		c.logger.Info("[UnlockCheck] csm.sh script executed successfully")
		return scriptResults
	}

	// Script failed - return default Unknown results
	c.logger.Error("[UnlockCheck] csm.sh script failed, returning Unknown for all services")
	return defaultResults
}

// runCSMScript executes the embedded csm.sh script locally, returns results or nil if failed
func (c *Checker) runCSMScript() *UnlockCheckResults {
	c.logger.Info("[UnlockCheck] Executing embedded csm.sh script (100% same logic as csm.sh)...")
	resultData, output, err := RunScript("ecycloudnode-unlock-")
	if err != nil {
		c.logger.Warnf("[UnlockCheck] %v, output: %s", err, string(output))
		return nil
	}

	var results UnlockCheckResults
	if err := json.Unmarshal(resultData, &results); err != nil {
		c.logger.Warnf("[UnlockCheck] Failed to parse result JSON: %v", err)
		return nil
	}

	c.logger.Info("[UnlockCheck] Embedded csm.sh script executed successfully")
	return &results
}

// RunScript 在新建的私有临时目录里执行内嵌脚本并返回结果 JSON：节点以 root 运行，
// 共享 /tmp 下的固定文件名可被其它用户预先创建或替换，从而伪造结果或借 root 执行命令。
func RunScript(prefix string) (result, output []byte, err error) {
	workDir, err := os.MkdirTemp("", prefix)
	if err != nil {
		return nil, nil, fmt.Errorf("创建检测临时目录失败：%w", err)
	}
	defer os.RemoveAll(workDir)
	scriptPath := filepath.Join(workDir, "check.sh")
	script := strings.ReplaceAll(CSM_SCRIPT, "/tmp/ecycloudnode_unlock_check", "${ECYCLOUDNODE_UNLOCK_TMP}/unlock_check")
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		return nil, nil, fmt.Errorf("写入检测脚本失败：%w", err)
	}
	execCmd := exec.Command("bash", scriptPath)
	execCmd.Env = append(os.Environ(), "LANG=en_US.UTF-8", "ECYCLOUDNODE_UNLOCK_TMP="+filepath.ToSlash(workDir))
	if output, err = execCmd.CombinedOutput(); err != nil {
		return nil, output, fmt.Errorf("执行检测脚本失败：%w", err)
	}
	if result, err = os.ReadFile(filepath.Join(workDir, "unlock_check_result.json")); err != nil {
		return nil, output, fmt.Errorf("读取检测结果失败：%w", err)
	}
	return result, output, nil
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
