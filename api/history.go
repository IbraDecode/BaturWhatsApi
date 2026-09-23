package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ibradecode/baturwhatsapi/events"
	"github.com/ibradecode/baturwhatsapi/protocol/binary"
)

// AckState is the delivery lifecycle of a message (T-105).
type AckState string

// Ack states.
const (
	AckPending   AckState = "pending"
	AckSent      AckState = "sent"
	AckDelivered AckState = "delivered"
	AckRead      AckState = "read"
	AckReceived  AckState = "received" // inbound
	AckFailed    AckState = "failed"
)

// StoredMessage is a persisted conversation entry.
type StoredMessage struct {
	ID        string   `json:"id"`
	Chat      string   `json:"chat"`
	Sender    string   `json:"sender"`
	Text      string   `json:"text"`
	Type      string   `json:"type"`
	FromMe    bool     `json:"from_me"`
	Ack       AckState `json:"ack"`
	Timestamp int64    `json:"ts"`
	Media     *Media   `json:"media,omitempty"`
}

// HistoryWindow is the per-chat ring size kept in storage.
const HistoryWindow = 256

// historyKey is the storage path for one chat's history.
func historyKey(sessionID, chat string) string {
	return "session/" + sessionID + "/history/" + chat
}

// HistoryStore keeps bounded, queryable per-chat message logs and updates
// ack state as receipts arrive. It subscribes to the bus and is safe for
// concurrent use.
type HistoryStore struct {
	batur *Batur
	lu    sync.Mutex // serialize load/modify/save per chat
}

// AttachHistory enables conversation persistence for the session (called
// from Batur.New when Options.History is true).
func (b *Batur) AttachHistory() *HistoryStore {
	h := &HistoryStore{batur: b}
	b.history = h
	b.histSubs = append(b.histSubs,
		b.bus.MustSubscribe(events.MessageReceived, 512, events.PolicyDropOldest, h.onInbound),
		b.bus.MustSubscribe(events.MessageSent, 512, events.PolicyDropOldest, h.onSent),
		b.bus.MustSubscribe(events.MessageAck, 512, events.PolicyDropOldest, h.onAck),
		b.bus.MustSubscribe(events.MessageUpdated, 512, events.PolicyDropOldest, h.onUpdated),
	)
	return h
}

func (h *HistoryStore) onInbound(_ context.Context, ev events.Event) {
	node, ok := ev.Data.(binary.Node)
	if !ok {
		return
	}
	msg := toMessage(node, ev.Session)
	if msg.ID == "" {
		return
	}
	sm := StoredMessage{
		ID: msg.ID, Chat: msg.Chat.JID, Text: msg.Text,
		Type: msg.Type, Ack: AckReceived, Timestamp: msgTS(node),
	}
	if msg.Sender.JID != "" {
		sm.Sender = msg.Sender.JID
	}
	if msg.Media != nil {
		md := *msg.Media
		sm.Media = &md
	}
	h.upsert(ev.Session, sm)
}

func (h *HistoryStore) onSent(_ context.Context, ev events.Event) {
	msg, ok := ev.Data.(Message)
	if !ok {
		return
	}
	h.upsert(ev.Session, StoredMessage{
		ID: msg.ID, Chat: msg.Chat.JID, Text: msg.Text, Type: msg.Type,
		FromMe: true, Ack: AckSent, Timestamp: msg.Stamp.Unix(),
	})
}

func (h *HistoryStore) onAck(_ context.Context, ev events.Event) {
	node, ok := ev.Data.(binary.Node)
	if !ok {
		return
	}
	id, _ := node.StringAttr("id")
	if id == "" {
		return
	}
	ack := AckDelivered
	switch strings.ToLower(node.MustStringAttr("type")) {
	case "read":
		ack = AckRead
	case "played":
		ack = AckRead
	case "":
		if node.MustStringAttr("to") != "" {
			ack = AckDelivered
		}
	}
	h.setAck(ev.Session, id, ack)
}

func (h *HistoryStore) onUpdated(_ context.Context, ev events.Event) {
	if node, ok := ev.Data.(binary.Node); ok {
		if id, _ := node.StringAttr("id"); id != "" {
			h.setAck(ev.Session, id, AckRead)
		}
	}
}

func msgTS(node binary.Node) int64 {
	if t, ok := node.StringAttr("t"); ok {
		var v int64
		for _, r := range t {
			if r < '0' || r > '9' {
				return time.Now().Unix()
			}
			v = v*10 + int64(r-'0')
		}
		return v
	}
	return time.Now().Unix()
}

// upsert inserts or replaces a message by id in the chat's bounded log.
func (h *HistoryStore) upsert(sessionID string, m StoredMessage) error {
	if h.batur == nil || m.Chat == "" {
		return nil
	}
	h.lu.Lock()
	defer h.lu.Unlock()
	ctx := context.Background()
	list := h.loadLocked(ctx, sessionID, m.Chat)
	replaced := false
	for i := range list {
		if list[i].ID == m.ID {
			if m.Ack == "" {
				m.Ack = list[i].Ack
			}
			list[i] = m
			replaced = true
			break
		}
	}
	if !replaced {
		list = append(list, m)
	}
	if len(list) > HistoryWindow {
		list = list[len(list)-HistoryWindow:]
	}
	return h.saveLocked(ctx, sessionID, m.Chat, list)
}

func (h *HistoryStore) setAck(sessionID, msgID string, ack AckState) error {
	if sessionID == "" || msgID == "" {
		return nil
	}
	h.lu.Lock()
	defer h.lu.Unlock()
	ctx := context.Background()
	chats, err := h.batur.opts.Store.List(ctx, "session/"+sessionID+"/history/")
	if err != nil {
		return err
	}
	for _, k := range chats {
		chat := strings.TrimPrefix(k, "session/"+sessionID+"/history/")
		list := h.loadLocked(ctx, sessionID, chat)
		changed := false
		for i := range list {
			if list[i].ID == msgID && list[i].FromMe {
				if ackRank(ack) >= ackRank(list[i].Ack) {
					list[i].Ack = ack
					changed = true
				}
			}
		}
		if changed {
			return h.saveLocked(ctx, sessionID, chat, list)
		}
	}
	return nil
}

func ackRank(a AckState) int {
	switch a {
	case AckFailed:
		return -1
	case "", AckReceived:
		return 0
	case AckSent:
		return 1
	case AckDelivered:
		return 2
	case AckRead:
		return 3
	}
	return 0
}

// History returns the newest `limit` messages of a chat (chronological).
func (b *Batur) History(ctx context.Context, sessionID, chat string, limit int) ([]StoredMessage, error) {
	if b.history == nil {
		return nil, errors.New("batur: history not enabled")
	}
	list := b.history.loadLocked(ctx, sessionID, chat)
	if limit <= 0 || limit >= len(list) {
		return list, nil
	}
	return list[len(list)-limit:], nil
}

// HistoryOne scans the session's stored history for a message by id. If
// chat is non-empty the search is bounded to that chat; otherwise it
// walks every chat the session knows about. Returns ErrUnknownMessage
// when no entry matches.
var ErrUnknownMessage = errors.New("batur: message not found in history")

func (b *Batur) HistoryOne(ctx context.Context, sessionID, msgID, chat string) (*StoredMessage, error) {
	if b.history == nil {
		return nil, errors.New("batur: history not enabled")
	}
	if chat != "" {
		list := b.history.loadLocked(ctx, sessionID, chat)
		for i := range list {
			if list[i].ID == msgID {
				return &list[i], nil
			}
		}
		return nil, ErrUnknownMessage
	}
	chats, err := b.RecentChats(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	for _, c := range chats {
		list := b.history.loadLocked(ctx, sessionID, c)
		for i := range list {
			if list[i].ID == msgID {
				return &list[i], nil
			}
		}
	}
	return nil, ErrUnknownMessage
}

// RecentChats lists chat JIDs that have stored history for a session.
func (b *Batur) RecentChats(ctx context.Context, sessionID string) ([]string, error) {
	if b.history == nil {
		return nil, errors.New("batur: history not enabled")
	}
	keys, err := b.opts.Store.List(ctx, "session/"+sessionID+"/history/")
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, strings.TrimPrefix(k, "session/"+sessionID+"/history/"))
	}
	sort.Strings(out)
	return out, nil
}

func (h *HistoryStore) loadLocked(ctx context.Context, sessionID, chat string) []StoredMessage {
	raw, err := h.batur.opts.Store.Get(ctx, historyKey(sessionID, chat))
	if err != nil {
		return nil
	}
	var list []StoredMessage
	if json.Unmarshal(raw, &list) != nil {
		return nil
	}
	return list
}

func (h *HistoryStore) saveLocked(ctx context.Context, sessionID, chat string, list []StoredMessage) error {
	raw, err := json.Marshal(list)
	if err != nil {
		return fmt.Errorf("batur: marshal history: %w", err)
	}
	return h.batur.opts.Store.Set(ctx, historyKey(sessionID, chat), raw)
}
