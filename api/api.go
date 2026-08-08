// Package api contains all the api used by ECYCloudNode
// To implement an api , one needs to implement the interface below.

package api

// API is the interface for different panel's api.
type API interface {
	GetNodeInfo() (nodeInfo *NodeInfo, err error)
	// GetECYCloudNodeCertConfig returns optional global ECYCloudNode certificate
	// configuration provided by the panel (for example, Cloudflare
	// DNS provider and its DNS-01 environment variables).
	GetECYCloudNodeCertConfig() (certConfig *ECYCloudNodeCertConfig, err error)
	// GetGlobalLimitConfig returns the panel-managed Redis connection
	// info (site IP and Redis password) for the global device limit.
	GetGlobalLimitConfig() (globalLimitConfig *GlobalLimitConfig, err error)
	GetUserList() (userList *[]UserInfo, err error)
	ReportNodeStatus(nodeStatus *NodeStatus) (err error)
	ReportNodeOnlineUsers(onlineUser *[]OnlineUser) (err error)
	ReportUserTraffic(userTraffic *[]UserTraffic) (err error)
	Describe() ClientInfo
	GetNodeRule() (ruleList *[]DetectRule, err error)
	GetExemptUsers() (exemptUsers []ExemptUser, err error)
	ReportIllegal(detectResultList *[]DetectResult) (err error)
	Debug()
	// GetUnlockCheckConfig returns the streaming unlock check configuration
	// from the panel, including the check interval in hours.
	GetUnlockCheckConfig() (config *UnlockCheckConfig, err error)
	// ReportUnlockCheckResult reports the streaming unlock check results
	// to the panel for the current node.
	ReportUnlockCheckResult(result string) error
	// ReportUnlockCheckResultForNode reports the streaming unlock check results
	// to the panel for a specific node ID.
	ReportUnlockCheckResultForNode(nodeID int, result string) error
}
