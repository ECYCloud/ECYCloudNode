package limiter

import "strings"

type ReclaimGrant struct {
	Granted    bool
	TargetSlot string
}

var reclaimConsumer func(int, string) (bool, string)

func SetReclaimConsumer(fn func(int, string) (bool, string)) {
	reclaimConsumer = fn
}

func ConsumeReclaimGrant(uid int, slot string) ReclaimGrant {
	slot = strings.TrimSpace(slot)
	if uid <= 0 || slot == "" || reclaimConsumer == nil {
		return ReclaimGrant{}
	}
	ok, targetSlot := reclaimConsumer(uid, slot)
	if !ok {
		return ReclaimGrant{}
	}
	return ReclaimGrant{Granted: true, TargetSlot: strings.TrimSpace(targetSlot)}
}
