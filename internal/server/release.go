package server

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	maxReleaseResponse   = 2 << 20
	maxReleaseAssetBytes = 64 << 20
	releaseCacheTTL      = 15 * time.Minute
)

var errReleaseAssetNotFound = errors.New("release asset not found")

var (
	repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	sha256Pattern     = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
)

type releaseAsset struct {
	Name        string
	DownloadURL string
	SHA256      string
}

type releaseBundle struct {
	Version     string
	HTMLURL     string
	PublishedAt time.Time
	Assets      map[string]releaseAsset
}

type githubRelease struct {
	TagName     string    `json:"tag_name"`
	HTMLURL     string    `json:"html_url"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

func (s *Server) handleReleaseDownload(w http.ResponseWriter, r *http.Request) {
	body, err := s.cachedReleaseDownload(r.PathValue("name"))
	if errors.Is(err, errReleaseAssetNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.logger.Warn("release download failed", "name", r.PathValue("name"), "error", err)
		http.Error(w, "release asset unavailable", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	controller := http.NewResponseController(w)
	_ = controller.SetWriteDeadline(time.Now().Add(3 * time.Minute))
	_, _ = w.Write(body)
}

func logicalReleaseName(name string) (arch string, checksums bool, ok bool) {
	switch name {
	case "checksums.txt":
		return "", true, true
	case "nginx-atlas_linux_amd64.tar.gz":
		return "amd64", false, true
	case "nginx-atlas_linux_arm64.tar.gz":
		return "arm64", false, true
	default:
		return "", false, false
	}
}

func renderLogicalChecksums(release releaseBundle) []byte {
	var builder strings.Builder
	for _, arch := range []string{"amd64", "arm64"} {
		asset, ok := release.Assets[arch]
		if !ok || !sha256Pattern.MatchString(asset.SHA256) {
			continue
		}
		fmt.Fprintf(&builder, "%s  nginx-atlas_linux_%s.tar.gz\n", strings.ToLower(asset.SHA256), arch)
	}
	return []byte(builder.String())
}

func (s *Server) cachedReleaseDownload(name string) ([]byte, error) {
	arch, checksums, ok := logicalReleaseName(name)
	if !ok {
		return nil, errReleaseAssetNotFound
	}
	s.releaseCacheMu.Lock()
	defer s.releaseCacheMu.Unlock()
	if s.releaseFiles != nil && time.Since(s.releaseCachedAt) < releaseCacheTTL {
		if body, found := s.releaseFiles[name]; found {
			return append([]byte(nil), body...), nil
		}
	} else {
		s.releaseFiles = map[string][]byte{}
		s.releaseCacheVersion = ""
	}
	fetchCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	release, err := s.fetchLatestRelease(fetchCtx)
	if err != nil {
		return nil, err
	}
	if s.releaseCacheVersion != release.Version {
		s.releaseFiles = map[string][]byte{}
		s.releaseCacheVersion = release.Version
	}
	s.releaseFiles["checksums.txt"] = renderLogicalChecksums(release)
	s.releaseCachedAt = time.Now()
	if checksums {
		return append([]byte(nil), s.releaseFiles["checksums.txt"]...), nil
	}
	asset, found := release.Assets[arch]
	if !found {
		return nil, errReleaseAssetNotFound
	}
	body, err := fetchLimited(fetchCtx, asset.DownloadURL, maxReleaseAssetBytes, 2*time.Minute)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != strings.ToLower(asset.SHA256) {
		return nil, errors.New("release asset checksum mismatch")
	}
	s.releaseFiles[name] = body
	return append([]byte(nil), body...), nil
}

func (s *Server) handleReleaseInfo(w http.ResponseWriter, r *http.Request) {
	release, err := s.fetchLatestRelease(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, "无法读取 GitHub 最新发行版", "release_unavailable", map[string]string{"reason": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"current_version":  s.config.Version,
		"latest_version":   release.Version,
		"update_available": versionUpdateAvailable(s.config.Version, release.Version),
		"published_at":     release.PublishedAt,
		"html_url":         release.HTMLURL,
		"repository":       s.config.Repository,
	})
}

func (s *Server) fetchLatestRelease(ctx context.Context) (releaseBundle, error) {
	repository := strings.TrimSpace(s.config.Repository)
	if !repositoryPattern.MatchString(repository) {
		return releaseBundle{}, errors.New("configured repository is invalid")
	}
	base, err := url.Parse(strings.TrimRight(s.config.ReleaseAPIURL, "/"))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return releaseBundle{}, errors.New("release API URL is invalid")
	}
	base.Path = path.Join(base.Path, "repos", repository, "releases", "latest")
	var response githubRelease
	if err := fetchJSON(ctx, base.String(), &response); err != nil {
		return releaseBundle{}, err
	}
	version := strings.TrimSpace(strings.TrimPrefix(response.TagName, "v"))
	if version == "" {
		return releaseBundle{}, errors.New("latest release has no version tag")
	}
	result := releaseBundle{Version: version, HTMLURL: response.HTMLURL, PublishedAt: response.PublishedAt, Assets: make(map[string]releaseAsset)}
	checksumURL := ""
	for _, asset := range response.Assets {
		name := strings.ToLower(asset.Name)
		if name == "checksums.txt" {
			checksumURL = asset.BrowserDownloadURL
			continue
		}
		for _, arch := range []string{"amd64", "arm64"} {
			if strings.HasSuffix(name, "linux_"+arch+".tar.gz") {
				result.Assets[arch] = releaseAsset{Name: asset.Name, DownloadURL: asset.BrowserDownloadURL}
			}
		}
	}
	if checksumURL == "" {
		return releaseBundle{}, errors.New("latest release is missing checksums.txt")
	}
	checksums, err := fetchBytes(ctx, checksumURL, maxReleaseResponse)
	if err != nil {
		return releaseBundle{}, fmt.Errorf("download release checksums: %w", err)
	}
	parsed := parseChecksums(checksums)
	for arch, asset := range result.Assets {
		asset.SHA256 = parsed[asset.Name]
		if !sha256Pattern.MatchString(asset.SHA256) {
			delete(result.Assets, arch)
			continue
		}
		result.Assets[arch] = asset
	}
	if len(result.Assets) == 0 {
		return releaseBundle{}, errors.New("latest release has no verified Linux asset")
	}
	return result, nil
}

func fetchLimited(ctx context.Context, source string, limit int64, timeout time.Duration) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "*/*")
	request.Header.Set("User-Agent", "nginx-atlas-controller")
	client := &http.Client{Timeout: timeout}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return nil, fmt.Errorf("upstream returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, errors.New("upstream response is too large")
	}
	return body, nil
}

func fetchJSON(ctx context.Context, source string, target any) error {
	body, err := fetchBytes(ctx, source, maxReleaseResponse)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("decode release response: %w", err)
	}
	return nil
}

func fetchBytes(ctx context.Context, source string, limit int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "nginx-atlas-controller")
	client := &http.Client{Timeout: 20 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return nil, fmt.Errorf("upstream returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, errors.New("upstream response is too large")
	}
	return body, nil
}

func parseChecksums(data []byte) map[string]string {
	result := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 || !sha256Pattern.MatchString(fields[0]) {
			continue
		}
		result[strings.TrimPrefix(fields[1], "*")] = strings.ToLower(fields[0])
	}
	return result
}

func versionUpdateAvailable(current, latest string) bool {
	currentVersion, currentPrerelease, currentOK := parseReleaseVersion(current)
	latestVersion, latestPrerelease, latestOK := parseReleaseVersion(latest)
	if !currentOK || !latestOK {
		return false
	}
	for index := range currentVersion {
		if latestVersion[index] != currentVersion[index] {
			return latestVersion[index] > currentVersion[index]
		}
	}
	// A stable release supersedes a prerelease with the same numeric core.
	return currentPrerelease != "" && latestPrerelease == ""
}

func parseReleaseVersion(value string) ([3]int, string, bool) {
	var result [3]int
	value = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(value), "v"))
	if value == "" || value == "dev" {
		return result, "", false
	}
	value, _, _ = strings.Cut(value, "+")
	core, prerelease, _ := strings.Cut(value, "-")
	parts := strings.Split(core, ".")
	if len(parts) == 0 || len(parts) > len(result) {
		return result, "", false
	}
	for index, part := range parts {
		if part == "" {
			return result, "", false
		}
		number, err := strconv.Atoi(part)
		if err != nil || number < 0 {
			return result, "", false
		}
		result[index] = number
	}
	return result, prerelease, true
}
