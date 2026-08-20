package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/yayitinyu/nginx-atlas/internal/model"
)

func TestUpdatePersistsAndRollsBackCallbackErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	stateStore, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := stateStore.Update(func(state *model.State) error {
		state.Nodes["node_1"] = model.Node{ID: "node_1", Name: "Tokyo-02", CreatedAt: now}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("stop")
	if err := stateStore.Update(func(state *model.State) error {
		delete(state.Nodes, "node_1")
		return sentinel
	}); !errors.Is(err, sentinel) {
		t.Fatalf("expected callback error, got %v", err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.Snapshot().Nodes["node_1"]; !ok {
		t.Fatal("failed update changed persisted state")
	}
}

func TestSubscribeSignalsOnlyCommittedStateChanges(t *testing.T) {
	stateStore, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	revision, changes, cancel := stateStore.Subscribe()
	defer cancel()
	if revision != 0 {
		t.Fatalf("initial revision = %d, want 0", revision)
	}

	sentinel := errors.New("stop")
	if err := stateStore.Update(func(state *model.State) error {
		state.Version++
		return sentinel
	}); !errors.Is(err, sentinel) {
		t.Fatalf("failed update returned %v", err)
	}
	assertNoStoreChange(t, changes)

	if err := stateStore.Update(func(_ *model.State) error { return nil }); err != nil {
		t.Fatal(err)
	}
	assertNoStoreChange(t, changes)

	if err := stateStore.Update(func(state *model.State) error {
		state.Nodes["node_2"] = model.Node{ID: "node_2", Name: "Osaka", CreatedAt: time.Now().UTC()}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-changes:
		if got != 1 {
			t.Fatalf("revision = %d, want 1", got)
		}
	case <-time.After(time.Second):
		t.Fatal("committed update did not notify subscriber")
	}
}

func assertNoStoreChange(t *testing.T, changes <-chan uint64) {
	t.Helper()
	select {
	case revision := <-changes:
		t.Fatalf("unexpected revision %d", revision)
	case <-time.After(25 * time.Millisecond):
	}
}
