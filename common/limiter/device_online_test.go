package limiter

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ECYCloud/ECYCloudNode/api"
)

func TestPurgeStaleDeviceIPs(t *testing.T) {
	ips := map[string]struct{}{"1.1.1.1": {}, "2.2.2.2": {}}
	active := map[string]time.Time{
		"1.1.1.1": time.Now().Add(-2 * time.Minute),
		"2.2.2.2": time.Now(),
	}
	fresh := PurgeStaleDeviceIPs(ips, active, time.Minute)
	if fresh != 1 {
		t.Fatalf("fresh=%d want 1", fresh)
	}
	if _, ok := ips["1.1.1.1"]; ok {
		t.Fatal("stale ip should be removed from onlineIPs")
	}
}

func TestStaleIPReleasesSlotForNewIP(t *testing.T) {
	l, key := newTestLimiter(t, 1)
	if _, _, reject := l.GetUserBucket("node", key, "1.1.1.1"); reject {
		t.Fatal("A should be admitted")
	}
	if _, _, reject := l.GetUserBucket("node", key, "2.2.2.2"); !reject {
		t.Fatal("B should be rejected while A is fresh")
	}
	makeStale(t, l, key, "1.1.1.1")
	if _, _, reject := l.GetUserBucket("node", key, "2.2.2.2"); reject {
		t.Fatal("B should be admitted after A expired")
	}
}

func TestVerifyOnlineDoesNotRefresh(t *testing.T) {
	l, key := newTestLimiter(t, 1)
	if _, _, reject := l.GetUserBucket("node", key, "1.1.1.1"); reject {
		t.Fatal("A should be admitted")
	}
	makeStale(t, l, key, "1.1.1.1")
	before := lastSeen(t, l, key, "1.1.1.1")
	if !l.VerifyOnline("node", key, "1.1.1.1") {
		t.Fatal("stale A with free slot should not be killed yet")
	}
	if after := lastSeen(t, l, key, "1.1.1.1"); after != before {
		t.Fatalf("VerifyOnline must not refresh LastSeen: before=%d after=%d", before, after)
	}
}

func newTestLimiter(t *testing.T, deviceLimit int) (*Limiter, string) {
	t.Helper()
	l := New()
	users := []api.UserInfo{{UID: 1, DeviceLimit: deviceLimit}}
	if err := l.AddInboundLimiter("node", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	return l, fmt.Sprintf("%s|%d", "node", 1)
}

func makeStale(t *testing.T, l *Limiter, userKey, ip string) {
	t.Helper()
	v, ok := l.InboundInfo.Load("node")
	if !ok {
		t.Fatal("inbound missing")
	}
	mv, ok := v.(*InboundInfo).UserOnlineIP.Load(userKey)
	if !ok {
		t.Fatal("user online map missing")
	}
	stale := time.Now().Unix() - int64(OnlineIPExpiry/time.Second) - 5
	mv.(*sync.Map).Store(ip, onlineEntry{UID: 1, LastSeen: stale})
}

func lastSeen(t *testing.T, l *Limiter, userKey, ip string) int64 {
	t.Helper()
	v, _ := l.InboundInfo.Load("node")
	mv, ok := v.(*InboundInfo).UserOnlineIP.Load(userKey)
	if !ok {
		return 0
	}
	ev, ok := mv.(*sync.Map).Load(ip)
	if !ok {
		return 0
	}
	return ev.(onlineEntry).LastSeen
}
