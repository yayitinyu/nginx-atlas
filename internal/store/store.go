package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/yayitinyu/nginx-atlas/internal/model"
)

const maxAuditEvents = 500

type Store struct {
	mu    sync.RWMutex
	path  string
	state model.State
}

func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("state path is required")
	}
	s := &Store{path: path, state: model.NewState()}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				return nil, fmt.Errorf("create state directory: %w", err)
			}
			if err := s.persist(s.state); err != nil {
				return nil, err
			}
			return s, nil
		}
		return nil, fmt.Errorf("read state: %w", err)
	}
	if len(data) == 0 {
		return nil, errors.New("state file is empty")
	}
	if err := json.Unmarshal(data, &s.state); err != nil {
		return nil, fmt.Errorf("decode state: %w", err)
	}
	normalize(&s.state)
	return s, nil
}

func (s *Store) Snapshot() model.State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return clone(s.state)
}

func (s *Store) Update(fn func(*model.State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	next := clone(s.state)
	if err := fn(&next); err != nil {
		return err
	}
	normalize(&next)
	if err := s.persist(next); err != nil {
		return err
	}
	s.state = next
	return nil
}

func AppendAudit(state *model.State, event model.AuditEvent) {
	state.Audit = append([]model.AuditEvent{event}, state.Audit...)
	if len(state.Audit) > maxAuditEvents {
		state.Audit = state.Audit[:maxAuditEvents]
	}
}

func (s *Store) persist(state model.State) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".state-*.json")
	if err != nil {
		return fmt.Errorf("create temporary state: %w", err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("protect temporary state: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write temporary state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync temporary state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary state: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("replace state atomically: %w", err)
	}
	committed = true
	return nil
}

func clone(state model.State) model.State {
	data, err := json.Marshal(state)
	if err != nil {
		panic(fmt.Sprintf("clone state: %v", err))
	}
	var copied model.State
	if err := json.Unmarshal(data, &copied); err != nil {
		panic(fmt.Sprintf("clone state: %v", err))
	}
	normalize(&copied)
	return copied
}

func normalize(state *model.State) {
	if state.Version == 0 {
		state.Version = 1
	}
	if state.Nodes == nil {
		state.Nodes = make(map[string]model.Node)
	}
	if state.Enrollments == nil {
		state.Enrollments = make(map[string]model.Enrollment)
	}
	if state.Domains == nil {
		state.Domains = make(map[string]model.Domain)
	}
	if state.Certificates == nil {
		state.Certificates = make(map[string]model.Certificate)
	}
	if state.DNSAccounts == nil {
		state.DNSAccounts = make(map[string]model.DNSAccount)
	}
	if state.ACMEAccounts == nil {
		state.ACMEAccounts = make(map[string]model.ACMEAccount)
	}
	if state.Jobs == nil {
		state.Jobs = make(map[string]model.Job)
	}
	if state.Audit == nil {
		state.Audit = make([]model.AuditEvent, 0)
	}
}
