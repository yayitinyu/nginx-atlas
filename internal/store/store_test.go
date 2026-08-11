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
