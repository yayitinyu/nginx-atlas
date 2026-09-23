package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/yayitinyu/nginx-atlas/internal/model"
	"github.com/yayitinyu/nginx-atlas/internal/protocol"
)

const nodeRemovedJobError = "node was removed before the task completed"

const minimumUpdateCandidateFreshness = 90 * time.Second

var errUpdateBatchFailed = errors.New("failed updates need review")

type skippedNodeUpdate struct {
	NodeID string `json:"node_id"`
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

func (s *Server) handleRenameNode(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	request.Name = strings.TrimSpace(request.Name)
	if len([]rune(request.Name)) < 2 || len([]rune(request.Name)) > 64 || strings.ContainsAny(request.Name, "\r\n\x00") {
		writeError(w, http.StatusBadRequest, "节点名称需为 2–64 个可见字符", "invalid_node_name", nil)
		return
	}
	var updated model.Node
	err := s.store.Update(func(state *model.State) error {
		node, ok := state.Nodes[r.PathValue("id")]
		if !ok {
			return errNotFound
		}
		node.Name = request.Name
		state.Nodes[node.ID] = node
		updated = node
		s.addAudit(state, "info", "node.renamed", "节点名称已更新", node.ID)
		return nil
	})
	if errors.Is(err, errNotFound) {
		writeError(w, http.StatusNotFound, "节点不存在", "not_found", nil)
		return
	}
	if err != nil {
		wrapStoreError(w, err)
		return
	}
	updated.SecretHash = ""
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleNodeUninstallCommand(w http.ResponseWriter, r *http.Request) {
	state := s.store.Snapshot()
	node, ok := state.Nodes[r.PathValue("id")]
	if !ok {
		writeError(w, http.StatusNotFound, "节点不存在", "not_found", nil)
		return
	}
	baseURL := s.publicURL(r)
	installerURL := strings.TrimRight(baseURL, "/") + "/install.sh"
	// The controller credential is revoked before this command is shown by the
	// remove-and-uninstall flow, so local cleanup must not require a second API call.
	command := fmt.Sprintf("curl -fsSL %s | sudo bash -s -- uninstall-agent --force-local", shellQuote(installerURL))
	writeJSON(w, http.StatusOK, map[string]any{
		"command":              command,
		"preserves_nginx":      true,
		"controller_installed": node.ControllerInstalled,
	})
}

func (s *Server) handleUpdateNodeAtlas(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("id")
	snapshot := s.store.Snapshot()
	node, ok := snapshot.Nodes[nodeID]
	if !ok || node.Status == model.NodeRevoked {
		writeError(w, http.StatusNotFound, "节点不存在或已撤销", "not_found", nil)
		return
	}
	release, err := s.fetchLatestRelease(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, "无法读取可验证的最新发行版", "release_unavailable", map[string]string{"reason": err.Error()})
		return
	}
	if strings.TrimSpace(node.AgentVersion) != "" && node.AgentVersion != "dev" && !versionUpdateAvailable(node.AgentVersion, release.Version) {
		writeError(w, http.StatusConflict, "节点已经是最新版本，或版本高于最新发行版", "already_up_to_date", nil)
		return
	}
	arch := normalizeNodeArch(node.Arch)
	asset, ok := release.Assets[arch]
	if !ok {
		writeError(w, http.StatusBadRequest, "最新发行版不支持该节点架构", "unsupported_arch", map[string]string{"arch": node.Arch})
		return
	}
	var job model.Job
	err = s.store.Update(func(state *model.State) error {
		current, ok := state.Nodes[nodeID]
		if !ok || current.Status == model.NodeRevoked {
			return errNotFound
		}
		if hasActiveNodeJob(state, nodeID, protocol.JobUpdateAtlas) {
			return errConflict
		}
		job, err = enqueueJob(state, nodeID, "", protocol.JobUpdateAtlas, protocol.UpdateAtlasPayload{
			DownloadURL: asset.DownloadURL, SHA256: asset.SHA256, ExpectedVersion: release.Version,
		})
		if err != nil {
			return err
		}
		s.addAudit(state, "info", "node.atlas-update.queued", "Nginx Atlas 更新任务已加入队列", nodeID, "", job.ID)
		return nil
	})
	if errors.Is(err, errConflict) {
		writeError(w, http.StatusConflict, "该节点已有 Atlas 更新任务", "job_exists", nil)
		return
	}
	if errors.Is(err, errNotFound) {
		writeError(w, http.StatusNotFound, "节点不存在", "not_found", nil)
		return
	}
	if err != nil {
		wrapStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

func (s *Server) handleUpdateAllNodesAtlas(w http.ResponseWriter, r *http.Request) {
	release, err := s.fetchLatestRelease(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, "无法读取可验证的最新发行版", "release_unavailable", map[string]string{"reason": err.Error()})
		return
	}
	jobs := make([]model.Job, 0)
	skipped := make([]skippedNodeUpdate, 0)
	failedNodeNames := make([]string, 0)
	deferred := 0
	phase := "canary"
	err = s.store.Update(func(state *model.State) error {
		latestJobs, active := latestAtlasUpdateJobs(state, release.Version)
		if active {
			return errConflict
		}
		failed := make([]string, 0)
		canarySucceeded := false
		for nodeID, job := range latestJobs {
			node, exists := state.Nodes[nodeID]
			if !exists || node.Status == model.NodeRevoked {
				continue
			}
			if job.Status == model.JobSucceeded && node.AgentVersion == release.Version {
				canarySucceeded = true
			} else if job.Status == model.JobFailed && node.AgentVersion != release.Version {
				failed = append(failed, node.Name)
			}
		}
		if len(failed) > 0 {
			sort.Strings(failed)
			failedNodeNames = failed
			return errUpdateBatchFailed
		}
		batchLimit := 1
		if canarySucceeded {
			batchLimit = 5
			phase = "batch"
		}
		// Node status may stay online for 15 minutes when report frequency is 300s.
		// Updates need a recent poll so a disconnected agent does not stall a batch.
		candidateFreshness := 3 * s.config.PollAfter
		if candidateFreshness < minimumUpdateCandidateFreshness {
			candidateFreshness = minimumUpdateCandidateFreshness
		}
		if offlineAfter := s.nodeOfflineAfter(*state); candidateFreshness > offlineAfter {
			candidateFreshness = offlineAfter
		}
		nodeIDs := make([]string, 0, len(state.Nodes))
		for nodeID, node := range state.Nodes {
			if node.Status != model.NodeRevoked {
				nodeIDs = append(nodeIDs, nodeID)
			}
		}
		sort.Slice(nodeIDs, func(i, j int) bool {
			left, right := state.Nodes[nodeIDs[i]], state.Nodes[nodeIDs[j]]
			if left.ControllerInstalled != right.ControllerInstalled {
				return !left.ControllerInstalled
			}
			return strings.ToLower(left.Name) < strings.ToLower(right.Name)
		})
		for _, nodeID := range nodeIDs {
			node := state.Nodes[nodeID]
			skip := func(reason string) {
				skipped = append(skipped, skippedNodeUpdate{NodeID: nodeID, Name: node.Name, Reason: reason})
			}
			if strings.TrimSpace(node.AgentVersion) != "" && node.AgentVersion != "dev" && !versionUpdateAvailable(node.AgentVersion, release.Version) {
				skip("current")
				continue
			}
			if node.Status != model.NodeOnline || node.LastSeenAt == nil || time.Since(*node.LastSeenAt) > candidateFreshness {
				skip("offline")
				continue
			}
			if !node.NginxHealthy {
				skip("unhealthy")
				continue
			}
			asset, supported := release.Assets[normalizeNodeArch(node.Arch)]
			if !supported {
				skip("unsupported_arch")
				continue
			}
			if hasAnyActiveNodeJob(state, nodeID) {
				skip("busy")
				continue
			}
			if len(jobs) >= batchLimit {
				deferred++
				continue
			}
			job, enqueueErr := enqueueJob(state, nodeID, "", protocol.JobUpdateAtlas, protocol.UpdateAtlasPayload{
				DownloadURL: asset.DownloadURL, SHA256: asset.SHA256, ExpectedVersion: release.Version,
			})
			if enqueueErr != nil {
				return enqueueErr
			}
			jobs = append(jobs, job)
			s.addAudit(state, "info", "node.atlas-update.queued", "Nginx Atlas 更新任务已加入队列", nodeID, "", job.ID)
		}
		return nil
	})
	if errors.Is(err, errConflict) {
		writeError(w, http.StatusConflict, "请等待当前节点更新批次完成", "update_batch_running", nil)
		return
	}
	if errors.Is(err, errUpdateBatchFailed) {
		writeError(w, http.StatusConflict, "上一批更新失败："+strings.Join(failedNodeNames, "、")+"。请先检查或重试", "update_batch_failed", map[string]string{"nodes": strings.Join(failedNodeNames, ",")})
		return
	}
	if err != nil {
		wrapStoreError(w, err)
		return
	}
	status := http.StatusOK
	if len(jobs) > 0 {
		status = http.StatusAccepted
	}
	writeJSON(w, status, map[string]any{"queued": len(jobs), "skipped": len(skipped), "skipped_nodes": skipped, "deferred": deferred, "phase": phase, "jobs": jobs, "version": release.Version})
}

func latestAtlasUpdateJobs(state *model.State, version string) (map[string]model.Job, bool) {
	latest := make(map[string]model.Job)
	active := false
	for _, job := range state.Jobs {
		if job.Type != protocol.JobUpdateAtlas {
			continue
		}
		if job.Status == model.JobQueued || job.Status == model.JobRunning {
			active = true
		}
		var payload protocol.UpdateAtlasPayload
		if json.Unmarshal(job.Payload, &payload) != nil || strings.TrimPrefix(payload.ExpectedVersion, "v") != version {
			continue
		}
		previous, ok := latest[job.NodeID]
		if !ok || job.CreatedAt.After(previous.CreatedAt) || (job.CreatedAt.Equal(previous.CreatedAt) && job.ID > previous.ID) {
			latest[job.NodeID] = job
		}
	}
	return latest, active
}

func hasAnyActiveNodeJob(state *model.State, nodeID string) bool {
	for _, job := range state.Jobs {
		if job.NodeID == nodeID && (job.Status == model.JobQueued || job.Status == model.JobRunning) {
			return true
		}
	}
	return false
}

func (s *Server) handleUpdateNodeSystem(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("id")
	var job model.Job
	err := s.store.Update(func(state *model.State) error {
		node, ok := state.Nodes[nodeID]
		if !ok || node.Status == model.NodeRevoked {
			return errNotFound
		}
		if node.PackageManager != "apt" {
			return errors.New("only apt-based nodes are currently supported")
		}
		if hasActiveNodeJob(state, nodeID, protocol.JobUpdateSystem) {
			return errConflict
		}
		var err error
		job, err = enqueueJob(state, nodeID, "", protocol.JobUpdateSystem, protocol.UpdateSystemPayload{PackageManager: "apt"})
		if err != nil {
			return err
		}
		s.addAudit(state, "warning", "node.system-update.queued", "APT 软件包与 Nginx 更新任务已加入队列", nodeID, "", job.ID)
		return nil
	})
	if errors.Is(err, errConflict) {
		writeError(w, http.StatusConflict, "该节点已有系统更新任务", "job_exists", nil)
		return
	}
	if errors.Is(err, errNotFound) {
		writeError(w, http.StatusNotFound, "节点不存在", "not_found", nil)
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "无法创建系统更新任务", "system_update_unavailable", map[string]string{"reason": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

func normalizeNodeArch(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "amd64", "x86_64":
		return "amd64"
	case "arm64", "aarch64":
		return "arm64"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func hasActiveNodeJob(state *model.State, nodeID, jobType string) bool {
	for _, job := range state.Jobs {
		if job.NodeID == nodeID && job.Type == jobType && (job.Status == model.JobQueued || job.Status == model.JobRunning) {
			return true
		}
	}
	return false
}

func revokeNodeState(state *model.State, nodeID string, now time.Time) {
	node := state.Nodes[nodeID]
	node.Status = model.NodeRevoked
	node.RevokedAt = &now
	node.SecretHash = ""
	node.RunningJobID = ""
	appendNodeStatusSample(&node, model.NodeRevoked, now)
	state.Nodes[nodeID] = node

	for domainID, domain := range state.Domains {
		domain.SyncNodeIDs = removeString(domain.SyncNodeIDs, nodeID)
		if domain.NodeID == nodeID {
			domain.NodeID = ""
			domain.Enabled = false
			domain.Deleting = false
			domain.AutoRenew = false
			domain.LastError = nodeRemovedJobError
			domain.UpdatedAt = now
		}
		state.Domains[domainID] = domain
	}
	for certificateID, certificate := range state.Certificates {
		certificate.DeployedNodeIDs = removeString(certificate.DeployedNodeIDs, nodeID)
		if certificate.IssuerNodeID == nodeID {
			certificate.IssuerNodeID = ""
			certificate.AutoRenew = false
		}
		state.Certificates[certificateID] = certificate
	}

	for jobID, job := range state.Jobs {
		if job.NodeID != nodeID || (job.Status != model.JobQueued && job.Status != model.JobRunning) {
			continue
		}
		job.Status = model.JobFailed
		job.Error = nodeRemovedJobError
		job.FinishedAt = &now
		state.Jobs[jobID] = job
		restoreFailedDomainDeletion(state, job, job.Error, now)
		if domain, ok := state.Domains[job.DomainID]; ok {
			domain.LastError = job.Error
			domain.UpdatedAt = now
			state.Domains[domain.ID] = domain
		}
	}
}

func removeString(values []string, target string) []string {
	result := values[:0]
	for _, value := range values {
		if value != target {
			result = append(result, value)
		}
	}
	return append([]string(nil), result...)
}
