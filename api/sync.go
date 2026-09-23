// Runtime sync orchestration for the api layer: resumable snapshotting of
// contacts and chats into the engine store, emitted as domain events, and
// queryable back through typed accessors.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/ibradecode/baturwhatsapi/events"
	"github.com/ibradecode/baturwhatsapi/protocol/binary"
	"github.com/ibradecode/baturwhatsapi/storage"
	batusync "github.com/ibradecode/baturwhatsapi/sync"
)

// baturErrNotFound bridges the storage sentinel for errors.Is.
func baturErrNotFound() error { return storage.ErrNotFound }

// Contact is a public directory entry (domain model, not protocol).
type Contact struct {
	JID     string `json:"jid"`
	Name    string `json:"name"`
	Updated int64  `json:"updated,omitempty"`
}

// ChatSummary is a public conversation descriptor.
type ChatSummary struct {
	JID      string `json:"jid"`
	Unread   int    `json:"unread"`
	LastSync int64  `json:"last_sync,omitempty"`
}

// SyncOnReady auto-runs a full contacts+chats sync whenever a session
// reports ready (default false; opt in via Options).
type SyncOptions struct {
	Enabled  bool
	Interval time.Duration // periodic re-sync while online (0 = only on ready)
	PageSize int           // advisory
}

// snapshotKey is the storage path for a session's synced snapshot.
func snapshotKey(sessionID, kind string) string {
	return "session/" + sessionID + "/snapshot/" + kind
}

// RunSync performs a resumable contacts+chats sync for a session and stores
// the decoded snapshot. Safe to call repeatedly; resumes from checkpoints.
func (b *Batur) RunSync(ctx context.Context, sessionID string) error {
	sess := b.sup.Session(sessionID)
	if sess == nil {
		return ErrUnknownSession
	}
	runner := &batusync.Runner{Session: sessionID, Store: b.opts.Store, Bus: b.bus}

	var contacts []Contact
	var chats []ChatSummary

	runner.Stages = []batusync.Stage{
		{Name: "contacts", Fetch: b.pageFetcher(sessionID, "contacts", func(items []binary.Node) {
			for _, it := range items {
				contacts = append(contacts, Contact{
					JID:  it.MustStringAttr("jid"),
					Name: it.MustStringAttr("name"),
				})
			}
		})},
		{Name: "chats", Fetch: b.pageFetcher(sessionID, "chats", func(items []binary.Node) {
			for _, it := range items {
				un, _ := strconv.Atoi(it.MustStringAttr("unread"))
				chats = append(chats, ChatSummary{JID: it.MustStringAttr("jid"), Unread: un})
			}
		})},
	}
	if err := runner.Run(ctx); err != nil {
		return err
	}
	now := time.Now().UTC().Unix()
	for i := range contacts {
		contacts[i].Updated = now
	}
	for i := range chats {
		chats[i].LastSync = now
	}
	if err := b.saveSnapshot(ctx, sessionID, "contacts", contacts); err != nil {
		return err
	}
	if err := b.saveSnapshot(ctx, sessionID, "chats", chats); err != nil {
		return err
	}
	// Surface domain updates.
	for _, c := range contacts {
		_ = b.bus.Publish(ctx, events.Event{Type: events.ContactUpdated, Session: sessionID, Data: c})
	}
	for _, c := range chats {
		_ = b.bus.Publish(ctx, events.Event{Type: events.ChatUpdated, Session: sessionID, Data: c})
	}
	return nil
}

// pageFetcher returns a StageFunc that requests a sync page and decodes it.
func (b *Batur) pageFetcher(sessionID, stage string, sink func([]binary.Node)) batusync.StageFunc {
	return func(ctx context.Context, cursor string) (batusync.Page, error) {
		resp, err := b.RequestNode(ctx, sessionID, binary.Node{
			Tag: "iq",
			Attrs: binary.Attrs{
				"type": "get", "xmlns": "batur.sync", "stage": stage, "cursor": cursor,
			},
		})
		if err != nil {
			return batusync.Page{}, err
		}
		syncNode, ok := resp.ChildByTag("sync")
		if !ok {
			return batusync.Page{}, errors.New("batur: sync reply missing <sync>")
		}
		items := syncNode.Children()
		page := batusync.Page{Cursor: syncNode.MustStringAttr("cursor")}
		for range items {
			page.Items = append(page.Items, struct{}{})
		}
		if sink != nil {
			sink(items)
		}
		return page, nil
	}
}

// saveSnapshot persists a typed slice under the session's snapshot prefix.
func (b *Batur) saveSnapshot(ctx context.Context, sessionID, kind string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return b.opts.Store.Set(ctx, snapshotKey(sessionID, kind), raw)
}

// Contacts returns the last synced contact snapshot.
func (b *Batur) Contacts(ctx context.Context, sessionID string) ([]Contact, error) {
	var out []Contact
	if err := b.loadSnapshot(ctx, sessionID, "contacts", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Chats returns the last synced chat summary snapshot.
func (b *Batur) Chats(ctx context.Context, sessionID string) ([]ChatSummary, error) {
	var out []ChatSummary
	if err := b.loadSnapshot(ctx, sessionID, "chats", &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (b *Batur) loadSnapshot(ctx context.Context, sessionID, kind string, v any) error {
	raw, err := b.opts.Store.Get(ctx, snapshotKey(sessionID, kind))
	if errors.Is(err, baturErrNotFound()) {
		return nil // nothing synced yet -> empty slice
	}
	if err != nil {
		return fmt.Errorf("batur: load snapshot: %w", err)
	}
	return json.Unmarshal(raw, v)
}
