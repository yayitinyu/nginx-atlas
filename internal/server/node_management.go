package server

import (
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
	skipped := 0
	err = s.store.Update(func(state *model.State) error {
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
			if strings.TrimSpace(node.AgentVersion) != "" && node.AgentVersion != "dev" && !versionUpdateAvailable(node.AgentVersion, release.Version) {
				skipped++
				continue
			}
			asset, supported := release.Assets[normalizeNodeArch(node.Arch)]
			if !supported || hasActiveNodeJob(state, nodeID, protocol.JobUpdateAtlas) {
				skipped++
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
	if err != nil {
		wrapStoreError(w, err)
		return
	}
	status := http.StatusOK
	if len(jobs) > 0 {
		status = http.StatusAccepted
	}
	writeJSON(w, status, map[string]any{"queued": len(jobs), "skipped": skipped, "jobs": jobs, "version": release.Version})
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
