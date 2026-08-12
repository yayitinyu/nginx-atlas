package server

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/yayitinyu/nginx-atlas/internal/model"
)

const (
	minNodePollSeconds = 10
	maxNodePollSeconds = 300
	maxStatusSamples   = 16
)

type settingsView struct {
	NodePollSeconds int `json:"node_poll_seconds"`
}

func (s *Server) effectiveSettings(state model.State) settingsView {
	seconds := state.Settings.NodePollSeconds
	if seconds < minNodePollSeconds || seconds > maxNodePollSeconds {
		seconds = int(s.config.PollAfter.Seconds())
	}
	if seconds < minNodePollSeconds {
		seconds = minNodePollSeconds
	}
	return settingsView{NodePollSeconds: seconds}
}

func (s *Server) nodePollAfter(state model.State) time.Duration {
	return time.Duration(s.effectiveSettings(state).NodePollSeconds) * time.Second
}

func (s *Server) nodeOfflineAfter(state model.State) time.Duration {
	minimum := 3*s.nodePollAfter(state) + 15*time.Second
	if s.config.OfflineAfter > minimum {
		return s.config.OfflineAfter
	}
	return minimum
}

func (s *Server) handleSettings(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.effectiveSettings(s.store.Snapshot()))
}

func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var request settingsView
	if !decodeJSON(w, r, &request) {
		return
	}
	if request.NodePollSeconds < minNodePollSeconds || request.NodePollSeconds > maxNodePollSeconds {
		writeError(w, http.StatusBadRequest, "节点状态频率需为 10–300 秒", "invalid_node_poll_seconds", nil)
		return
	}
	if err := s.store.Update(func(state *model.State) error {
		state.Settings.NodePollSeconds = request.NodePollSeconds
		s.addAudit(state, "info", "settings.node-poll.updated", "节点状态频率已更新")
		return nil
	}); err != nil {
		wrapStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, request)
}

func (s *Server) handleManagementCommands(w http.ResponseWriter, r *http.Request) {
	installerURL := strings.TrimRight(s.publicURL(r), "/") + "/install.sh"
	writeJSON(w, http.StatusOK, map[string]string{
		"uninstall_node":       fmt.Sprintf("curl -fsSL %s | sudo bash -s -- uninstall-agent", shellQuote(installerURL)),
		"uninstall_controller": fmt.Sprintf("curl -fsSL %s | sudo bash -s -- uninstall-server", shellQuote(installerURL)),
	})
}

func appendNodeStatusSample(node *model.Node, status model.NodeStatus, observedAt time.Time) {
	node.StatusHistory = append(node.StatusHistory, model.NodeStatusSample{Status: status, ObservedAt: observedAt})
	if len(node.StatusHistory) > maxStatusSamples {
		node.StatusHistory = append([]model.NodeStatusSample(nil), node.StatusHistory[len(node.StatusHistory)-maxStatusSamples:]...)
	}
}
