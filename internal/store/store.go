package store

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"github.com/yayitinyu/nginx-atlas/internal/model"
)

const maxAuditEvents = 500

type Store struct {
	mu               sync.RWMutex
	path             string
	state            model.State
	revision         uint64
	nextSubscriberID uint64
	subscribers      map[uint64]chan uint64
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

func (s *Store) AdminPasswordHash() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.AdminPasswordHash
}

// Settings returns only controller settings, avoiding an O(total state) clone
// on public middleware and login endpoints.
func (s *Store) Settings() model.ControllerSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	settings := s.state.Settings
	settings.PanelAllowedCIDRs = append([]string(nil), settings.PanelAllowedCIDRs...)
	return settings
}

// NodeCredential returns the narrow credential record needed by node auth.
// Reported inventory and unrelated encrypted state are intentionally omitted.
func (s *Store) NodeCredential(nodeID string) (secretHash string, status model.NodeStatus, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	node, ok := s.state.Nodes[nodeID]
	if !ok {
		return "", "", false
	}
	return node.SecretHash, node.Status, true
}

func (s *Store) JobForNode(jobID, nodeID string) (model.Job, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	job, ok := s.state.Jobs[jobID]
	if !ok || job.NodeID != nodeID {
		return model.Job{}, false
	}
	job.Payload = append([]byte(nil), job.Payload...)
	return job, true
}

// HasUsableEnrollment performs the cheap read-only part of enrollment before
// Update clones and persists the state. The transaction still rechecks it to
// preserve one-time-token semantics under races.
func (s *Store) HasUsableEnrollment(tokenHash []byte, now time.Time) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, enrollment := range s.state.Enrollments {
		expected, err := decodeHexHash(enrollment.TokenHash)
		if err == nil && subtle.ConstantTimeCompare(tokenHash, expected) == 1 {
			return enrollment.UsedAt == nil && now.Before(enrollment.ExpiresAt)
		}
	}
	return false
}

func (s *Store) Update(fn func(*model.State) error) error {
	s.mu.Lock()
	next := clone(s.state)
	if err := fn(&next); err != nil {
		s.mu.Unlock()
		return err
	}
	normalize(&next)
	if reflect.DeepEqual(next, s.state) {
		s.mu.Unlock()
		return nil
	}
	if err := s.persist(next); err != nil {
		s.mu.Unlock()
		return err
	}
	s.state = next
	s.revision++
	revision := s.revision
	subscribers := make([]chan uint64, 0, len(s.subscribers))
	for _, subscriber := range s.subscribers {
		subscribers = append(subscribers, subscriber)
	}
	s.mu.Unlock()

	for _, subscriber := range subscribers {
		select {
		case subscriber <- revision:
		default:
		}
	}
	return nil
}

// Subscribe reports committed state revisions. Notifications are coalesced for
// slow consumers; callers should always read a fresh snapshot after a signal.
func (s *Store) Subscribe() (uint64, <-chan uint64, func()) {
	s.mu.Lock()
	if s.subscribers == nil {
		s.subscribers = make(map[uint64]chan uint64)
	}
	s.nextSubscriberID++
	id := s.nextSubscriberID
	changes := make(chan uint64, 1)
	s.subscribers[id] = changes
	revision := s.revision
	s.mu.Unlock()

	var once sync.Once
	cancel := func() {
		once.Do(func() {
			s.mu.Lock()
			delete(s.subscribers, id)
			s.mu.Unlock()
		})
	}
	return revision, changes, cancel
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

func decodeHexHash(value string) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256HashSize {
		return nil, errors.New("invalid hash")
	}
	return decoded, nil
}

const sha256HashSize = 32
