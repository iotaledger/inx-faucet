package nodebridge

import (
	"github.com/gohornet/hornet/pkg/model/milestone"
	"github.com/iotaledger/hive.go/events"
	inx "github.com/iotaledger/inx/go"
	iotago "github.com/iotaledger/iota.go/v3"
)

type TangleListener struct {
	blockSolidSyncEvent         *events.SyncEvent
	milestoneConfirmedSyncEvent *events.SyncEvent
}

func newTangleListener() *TangleListener {
	return &TangleListener{
		blockSolidSyncEvent:         events.NewSyncEvent(),
		milestoneConfirmedSyncEvent: events.NewSyncEvent(),
	}
}

func (t *TangleListener) RegisterBlockSolidEvent(blockID *iotago.BlockID) chan struct{} {
	return t.blockSolidSyncEvent.RegisterEvent(string(blockID[:]))
}

func (t *TangleListener) DeregisterBlockSolidEvent(blockID *iotago.BlockID) {
	t.blockSolidSyncEvent.DeregisterEvent(string(blockID[:]))
}

func (t *TangleListener) RegisterMilestoneConfirmedEvent(msIndex milestone.Index) chan struct{} {
	return t.milestoneConfirmedSyncEvent.RegisterEvent(msIndex)
}

func (t *TangleListener) DeregisterMilestoneConfirmedEvent(msIndex milestone.Index) {
	t.milestoneConfirmedSyncEvent.DeregisterEvent(msIndex)
}

func (t *TangleListener) processSolidBlock(metadata *inx.BlockMetadata) {
	t.blockSolidSyncEvent.Trigger(string(metadata.GetBlockId().GetId()))
}

func (t *TangleListener) processConfirmedMilestone(ms *inx.Milestone) {
	t.milestoneConfirmedSyncEvent.Trigger(milestone.Index(ms.GetMilestoneInfo().GetMilestoneIndex()))
}
