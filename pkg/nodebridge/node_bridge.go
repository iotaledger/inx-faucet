package nodebridge

import (
	"context"
	"io"
	"sync"
	"time"

	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/iotaledger/hive.go/events"
	"github.com/iotaledger/hive.go/logger"
	inx "github.com/iotaledger/inx/go"
	iotago "github.com/iotaledger/iota.go/v3"
	"github.com/iotaledger/iota.go/v3/nodeclient"
)

type NodeBridge struct {
	Logger         *logger.Logger
	Client         inx.INXClient
	NodeConfig     *inx.NodeConfiguration
	TangleListener *TangleListener
	Events         *Events

	isSyncedMutex      sync.RWMutex
	latestMilestone    *inx.MilestoneInfo
	confirmedMilestone *inx.MilestoneInfo
}

type Events struct {
	MessageSolid              *events.Event
	ConfirmedMilestoneChanged *events.Event
	LedgerUpdated             *events.Event
}

func INXMessageMetadataCaller(handler interface{}, params ...interface{}) {
	handler.(func(metadata *inx.MessageMetadata))(params[0].(*inx.MessageMetadata))
}

func INXMilestoneCaller(handler interface{}, params ...interface{}) {
	handler.(func(milestone *inx.Milestone))(params[0].(*inx.Milestone))
}

func INXLedgerUpdateCaller(handler interface{}, params ...interface{}) {
	handler.(func(update *inx.LedgerUpdate))(params[0].(*inx.LedgerUpdate))
}

func NewNodeBridge(ctx context.Context, client inx.INXClient, logger *logger.Logger) (*NodeBridge, error) {
	logger.Info("Connecting to node and reading protocol parameters...")

	retryBackoff := func(_ uint) time.Duration {
		return 1 * time.Second
	}

	nodeConfig, err := client.ReadNodeConfiguration(ctx, &inx.NoParams{}, grpc_retry.WithMax(5), grpc_retry.WithBackoff(retryBackoff))
	if err != nil {
		return nil, err
	}

	nodeStatus, err := client.ReadNodeStatus(ctx, &inx.NoParams{})
	if err != nil {
		return nil, err
	}

	return &NodeBridge{
		Logger:         logger,
		Client:         client,
		NodeConfig:     nodeConfig,
		TangleListener: newTangleListener(),
		Events: &Events{
			MessageSolid:              events.NewEvent(INXMessageMetadataCaller),
			ConfirmedMilestoneChanged: events.NewEvent(INXMilestoneCaller),
			LedgerUpdated:             events.NewEvent(INXLedgerUpdateCaller),
		},
		latestMilestone:    nodeStatus.GetLatestMilestone(),
		confirmedMilestone: nodeStatus.GetConfirmedMilestone(),
	}, nil
}

func (n *NodeBridge) Run(ctx context.Context) {
	c, cancel := context.WithCancel(ctx)
	defer cancel()
	go n.listenToConfirmedMilestone(c, cancel)
	go n.listenToLatestMilestone(c, cancel)
	go n.listenToSolidMessages(c, cancel)
	go n.listenToLedgerUpdates(c, cancel)
	<-c.Done()
}

func (n *NodeBridge) IsNodeSynced() bool {
	n.isSyncedMutex.RLock()
	defer n.isSyncedMutex.RUnlock()

	if n.confirmedMilestone == nil || n.latestMilestone == nil {
		return false
	}

	return n.latestMilestone.GetMilestoneIndex() == n.confirmedMilestone.GetMilestoneIndex()
}

func (n *NodeBridge) EmitMessage(ctx context.Context, message *iotago.Message) (iotago.MessageID, error) {

	msg, err := inx.WrapMessage(message)
	if err != nil {
		return iotago.MessageID{}, err
	}

	response, err := n.Client.SubmitMessage(ctx, msg)
	if err != nil {
		return iotago.MessageID{}, err
	}

	return response.Unwrap(), nil
}

func (n *NodeBridge) INXNodeClient() *nodeclient.Client {
	return inx.NewNodeclientOverINX(n.Client)
}

func (n *NodeBridge) MessageMetadata(ctx context.Context, messageID iotago.MessageID) (*inx.MessageMetadata, error) {
	return n.Client.ReadMessageMetadata(ctx, inx.NewMessageId(messageID))
}

func (n *NodeBridge) listenToSolidMessages(ctx context.Context, cancel context.CancelFunc) error {
	defer cancel()
	filter := &inx.MessageFilter{}
	stream, err := n.Client.ListenToSolidMessages(ctx, filter)
	if err != nil {
		return err
	}
	for {
		messageMetadata, err := stream.Recv()
		if err != nil {
			if err == io.EOF || status.Code(err) == codes.Canceled {
				break
			}
			n.Logger.Errorf("listenToSolidMessages: %s", err.Error())
			break
		}
		if ctx.Err() != nil {
			break
		}
		n.processSolidMessage(messageMetadata)
	}
	return nil
}

func (n *NodeBridge) listenToLatestMilestone(ctx context.Context, cancel context.CancelFunc) error {
	defer cancel()
	stream, err := n.Client.ListenToLatestMilestone(ctx, &inx.NoParams{})
	if err != nil {
		return err
	}
	for {
		milestone, err := stream.Recv()
		if err != nil {
			if err == io.EOF || status.Code(err) == codes.Canceled {
				break
			}
			n.Logger.Errorf("listenToLatestMilestone: %s", err.Error())
			break
		}
		if ctx.Err() != nil {
			break
		}
		n.processLatestMilestone(milestone)
	}
	return nil
}

func (n *NodeBridge) listenToConfirmedMilestone(ctx context.Context, cancel context.CancelFunc) error {
	defer cancel()
	stream, err := n.Client.ListenToConfirmedMilestone(ctx, &inx.NoParams{})
	if err != nil {
		return err
	}
	for {
		milestone, err := stream.Recv()
		if err != nil {
			if err == io.EOF || status.Code(err) == codes.Canceled {
				break
			}
			n.Logger.Errorf("listenToConfirmedMilestone: %s", err.Error())
			break
		}
		if ctx.Err() != nil {
			break
		}
		n.processConfirmedMilestone(milestone)
	}
	return nil
}

func (n *NodeBridge) listenToLedgerUpdates(ctx context.Context, cancel context.CancelFunc) error {
	defer cancel()
	stream, err := n.Client.ListenToLedgerUpdates(ctx, &inx.LedgerRequest{})
	if err != nil {
		return err
	}
	for {
		update, err := stream.Recv()
		if err != nil {
			if err == io.EOF || status.Code(err) == codes.Canceled {
				break
			}
			n.Logger.Warnf("listenToLedgerUpdates: %s", err.Error())
			break
		}
		if ctx.Err() != nil {
			break
		}
		n.processLedgerUpdate(update)
	}
	return nil
}

func (n *NodeBridge) processSolidMessage(metadata *inx.MessageMetadata) {
	n.TangleListener.processSolidMessage(metadata)
	n.Events.MessageSolid.Trigger(metadata)
}

func (n *NodeBridge) processLatestMilestone(ms *inx.Milestone) {
	n.isSyncedMutex.Lock()
	n.latestMilestone = ms.GetMilestoneInfo()
	n.isSyncedMutex.Unlock()
}

func (n *NodeBridge) processConfirmedMilestone(ms *inx.Milestone) {
	n.isSyncedMutex.Lock()
	n.confirmedMilestone = ms.GetMilestoneInfo()
	n.isSyncedMutex.Unlock()

	n.TangleListener.processConfirmedMilestone(ms)
	n.Events.ConfirmedMilestoneChanged.Trigger(ms)
}

func (n *NodeBridge) processLedgerUpdate(update *inx.LedgerUpdate) {
	n.Events.LedgerUpdated.Trigger(update)
}
