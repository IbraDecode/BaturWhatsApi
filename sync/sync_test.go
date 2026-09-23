package sync

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/ibradecode/baturwhatsapi/events"
	"github.com/ibradecode/baturwhatsapi/storage"
)

func stages(fetches *int, failAt map[string]int) []Stage {
	calls := map[string]int{}
	mk := func(name string, total int, size int) Stage {
		return Stage{Name: name, Fetch: func(_ context.Context, cursor string) (Page, error) {
			*fetches++
			calls[name]++
			if failAt != nil && failAt[name] == calls[name] {
				return Page{}, errors.New("boom mid-" + name)
			}
			start := 0
			if cursor != "" {
				fmt.Sscanf(cursor, "%d", &start)
			}
			next := start + size
			if next > total {
				next = total
			}
			items := make([]any, 0, next-start)
			for i := start; i < next; i++ {
				items = append(items, fmt.Sprintf("%s-%d", name, i))
			}
			c := ""
			if next < total {
				c = fmt.Sprintf("%d", next)
			}
			return Page{Items: items, Cursor: c}, nil
		}}
	}
	return []Stage{mk("contacts", 10, 3), mk("chats", 7, 4)}
}

func TestRunCompletesAndCounts(t *testing.T) {
	store := storage.NewMemory()
	bus := events.New()
	defer bus.Close()
	var failed bool
	bus.MustSubscribe(events.SyncFailed, 4, events.PolicyBlock,
		func(context.Context, events.Event) { failed = true })
	r := &Runner{Session: "s1", Store: store, Bus: bus}
	n := 0
	r.Stages = stages(&n, nil)
	if err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if failed {
		t.Fatal("unexpected failure event")
	}
	prog := r.Progress(context.Background())
	if len(prog) != 2 {
		t.Fatalf("progress = %+v", prog)
	}
	var items uint64
	for _, cp := range prog {
		if !cp.Complete {
			t.Fatalf("stage %s not complete", cp.Stage)
		}
		items += cp.Items
	}
	if items != 17 {
		t.Fatalf("items = %d want 17", items)
	}
}

func TestResumeFromCheckpoint(t *testing.T) {
	store := storage.NewMemory()
	r := &Runner{Session: "s2", Store: store}
	n := 0
	r.Stages = stages(&n, map[string]int{"chats": 2}) // succeed page 1, fail page 2
	err := r.Run(context.Background())
	if err == nil {
		t.Fatal("expected failure")
	}
	if n != 6 { // 4 contacts pages + 2 chats fetches
		t.Fatalf("fetches before failure = %d", n)
	}
	// contacts stage should be complete; chats cursor persisted at 4.
	prog := map[string]Checkpoint{}
	for _, cp := range r.Progress(context.Background()) {
		prog[cp.Stage] = cp
	}
	if !prog["contacts"].Complete || prog["contacts"].Items != 10 {
		t.Fatalf("contacts checkpoint wrong: %+v", prog["contacts"])
	}
	if prog["chats"].Cursor != "4" {
		t.Fatalf("chats cursor not persisted: %+v", prog["chats"])
	}
	// Resume with a fresh runner sharing storage.
	n2 := 0
	r2 := &Runner{Session: "s2", Store: store}
	r2.Stages = stages(&n2, nil)
	if err := r2.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, cp := range r2.Progress(context.Background()) {
		if !cp.Complete {
			t.Fatalf("stage %s incomplete after resume", cp.Stage)
		}
	}
	// chats resume: remaining 3 items = one page => single fetch.
	if n2 != 1 {
		t.Fatalf("resume refetched everything: fetches=%d", n2)
	}
}

func TestReset(t *testing.T) {
	store := storage.NewMemory()
	r := &Runner{Session: "s3", Store: store}
	n := 0
	r.Stages = stages(&n, nil)
	if err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := r.Reset(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.Progress(context.Background())) != 0 {
		t.Fatal("reset did not clear")
	}
}
