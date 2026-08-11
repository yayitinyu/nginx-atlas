package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/yayitinyu/nginx-atlas/internal/model"
	"github.com/yayitinyu/nginx-atlas/internal/nginxconfig"
)

const maxCloudflareResponse = 2 << 20

type cloudflareRecordRequest struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
	Comment string `json:"comment,omitempty"`
}

type cloudflareRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
}

type cloudflareZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cloudflareEnvelope struct {
	Success bool            `json:"success"`
	Result  json.RawMessage `json:"result"`
	Errors  []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

type cloudflareRecordResult struct {
	DNSAccountID string
	RecordType   string
	Content      string
	Proxied      bool
}

func (s *Server) upsertCloudflareRecord(ctx context.Context, state model.State, request createDomainRequest) (cloudflareRecordResult, error) {
	accountID := strings.TrimSpace(request.CloudflareDNSAccountID)
	if accountID == "" {
		if account, ok := state.DNSAccounts[request.DNSAccountID]; ok && strings.EqualFold(account.Provider, "cloudflare") {
			accountID = account.ID
		} else {
			ids := make([]string, 0)
			for id, account := range state.DNSAccounts {
				if strings.EqualFold(account.Provider, "cloudflare") {
					ids = append(ids, id)
				}
			}
			sort.Strings(ids)
			if len(ids) > 0 {
				accountID = ids[0]
			}
		}
	}
	account, ok := state.DNSAccounts[accountID]
	if !ok || !strings.EqualFold(account.Provider, "cloudflare") {
		return cloudflareRecordResult{}, errors.New("请选择一个 Cloudflare DNS 账户")
	}
	plaintext, err := s.box.Open("dns-account:"+account.ID, account.CredentialsCiphertext)
	if err != nil {
		return cloudflareRecordResult{}, errors.New("Cloudflare DNS 账户凭据无法解密")
	}
	var credentials map[string]string
	if err := json.Unmarshal(plaintext, &credentials); err != nil {
		return cloudflareRecordResult{}, errors.New("Cloudflare DNS 账户凭据格式损坏")
	}
	token := firstCredential(credentials, "CLOUDFLARE_DNS_API_TOKEN", "CF_DNS_API_TOKEN", "CLOUDFLARE_API_TOKEN")
	if token == "" {
		return cloudflareRecordResult{}, errors.New("Cloudflare DNS 账户缺少 API Token")
	}
	node, ok := state.Nodes[request.NodeID]
	if !ok {
		return cloudflareRecordResult{}, errors.New("目标节点不存在")
	}
	content := strings.TrimSpace(request.CloudflareRecordContent)
	if content == "" {
		content = preferredNodeAddress(node.IPAddresses)
	}
	if content == "" {
		return cloudflareRecordResult{}, errors.New("目标节点尚未上报可用于 DNS 的 IP 地址")
	}
	recordType := strings.ToUpper(strings.TrimSpace(request.CloudflareRecordType))
	if recordType == "" {
		if ip := net.ParseIP(content); ip != nil && ip.To4() == nil {
			recordType = "AAAA"
		} else if net.ParseIP(content) != nil {
			recordType = "A"
		} else {
			recordType = "CNAME"
		}
	}
	if err := validateDNSRecordContent(recordType, content); err != nil {
		return cloudflareRecordResult{}, err
	}
	client, err := newCloudflareClient(s.config.CloudflareAPIURL, token)
	if err != nil {
		return cloudflareRecordResult{}, err
	}
	zone, err := client.findZone(ctx, request.Domain)
	if err != nil {
		return cloudflareRecordResult{}, err
	}
	records, err := client.listRecords(ctx, zone.ID, recordType, request.Domain)
	if err != nil {
		return cloudflareRecordResult{}, err
	}
	payload := cloudflareRecordRequest{
		Type: recordType, Name: request.Domain, Content: content, TTL: 1,
		Proxied: request.CloudflareProxied, Comment: "Managed by Nginx Atlas",
	}
	if len(records) > 1 {
		return cloudflareRecordResult{}, errors.New("Cloudflare 中存在多条同类型同名记录，请先手动整理")
	}
	if len(records) == 1 {
		if err := client.editRecord(ctx, zone.ID, records[0].ID, payload); err != nil {
			return cloudflareRecordResult{}, err
		}
	} else if err := client.createRecord(ctx, zone.ID, payload); err != nil {
		return cloudflareRecordResult{}, err
	}
	return cloudflareRecordResult{DNSAccountID: accountID, RecordType: recordType, Content: content, Proxied: request.CloudflareProxied}, nil
}

type cloudflareClient struct {
	base  *url.URL
	token string
	http  *http.Client
}

func newCloudflareClient(baseURL, token string) (*cloudflareClient, error) {
	base, err := url.Parse(strings.TrimRight(strings.TrimSpace(baseURL), "/"))
	if err != nil || base.Host == "" || (base.Scheme != "https" && !(base.Scheme == "http" && isLoopbackAddress(base.Hostname()))) {
		return nil, errors.New("Cloudflare API 地址无效")
	}
	return &cloudflareClient{base: base, token: token, http: &http.Client{Timeout: 20 * time.Second}}, nil
}

func (c *cloudflareClient) findZone(ctx context.Context, domain string) (cloudflareZone, error) {
	labels := strings.Split(domain, ".")
	for index := 0; index <= len(labels)-2; index++ {
		candidate := strings.Join(labels[index:], ".")
		query := url.Values{"name": []string{candidate}, "status": []string{"active"}}
		var zones []cloudflareZone
		if err := c.do(ctx, http.MethodGet, "/zones", query, nil, &zones); err != nil {
			return cloudflareZone{}, err
		}
		for _, zone := range zones {
			if strings.EqualFold(zone.Name, candidate) {
				return zone, nil
			}
		}
	}
	return cloudflareZone{}, errors.New("Cloudflare 账户中没有找到该域名所属的活动区域")
}

func (c *cloudflareClient) listRecords(ctx context.Context, zoneID, recordType, name string) ([]cloudflareRecord, error) {
	query := url.Values{"type": []string{recordType}, "name": []string{name}}
	var records []cloudflareRecord
	err := c.do(ctx, http.MethodGet, "/zones/"+url.PathEscape(zoneID)+"/dns_records", query, nil, &records)
	return records, err
}

func (c *cloudflareClient) createRecord(ctx context.Context, zoneID string, payload cloudflareRecordRequest) error {
	var record cloudflareRecord
	return c.do(ctx, http.MethodPost, "/zones/"+url.PathEscape(zoneID)+"/dns_records", nil, payload, &record)
}

func (c *cloudflareClient) editRecord(ctx context.Context, zoneID, recordID string, payload cloudflareRecordRequest) error {
	var record cloudflareRecord
	return c.do(ctx, http.MethodPatch, "/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(recordID), nil, payload, &record)
}

func (c *cloudflareClient) do(ctx context.Context, method, endpoint string, query url.Values, body, target any) error {
	requestURL := *c.base
	requestURL.Path = path.Join(c.base.Path, endpoint)
	requestURL.RawQuery = query.Encode()
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(payload)
	}
	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), reader)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("连接 Cloudflare API: %w", err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxCloudflareResponse+1))
	if err != nil {
		return err
	}
	if len(payload) > maxCloudflareResponse {
		return errors.New("Cloudflare API 响应过大")
	}
	var envelope cloudflareEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return fmt.Errorf("解析 Cloudflare API 响应: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || !envelope.Success {
		message := fmt.Sprintf("Cloudflare API 返回 HTTP %d", response.StatusCode)
		if len(envelope.Errors) > 0 && strings.TrimSpace(envelope.Errors[0].Message) != "" {
			message += ": " + truncate(envelope.Errors[0].Message, 240)
		}
		return errors.New(message)
	}
	if target != nil && len(envelope.Result) > 0 {
		if err := json.Unmarshal(envelope.Result, target); err != nil {
			return fmt.Errorf("解析 Cloudflare 记录: %w", err)
		}
	}
	return nil
}

func firstCredential(credentials map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(credentials[key]); value != "" {
			return value
		}
	}
	return ""
}

func preferredNodeAddress(addresses []string) string {
	var fallback string
	for _, value := range addresses {
		ip := net.ParseIP(strings.TrimSpace(value))
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		if fallback == "" {
			fallback = ip.String()
		}
		if ip.To4() != nil && !ip.IsPrivate() {
			return ip.String()
		}
	}
	return fallback
}

func validateDNSRecordContent(recordType, content string) error {
	switch recordType {
	case "A":
		if ip := net.ParseIP(content); ip == nil || ip.To4() == nil {
			return errors.New("A 记录内容必须是 IPv4 地址")
		}
	case "AAAA":
		if ip := net.ParseIP(content); ip == nil || ip.To4() != nil {
			return errors.New("AAAA 记录内容必须是 IPv6 地址")
		}
	case "CNAME":
		if _, err := nginxconfig.ConfigFileName(strings.TrimSuffix(strings.ToLower(content), ".")); err != nil {
			return errors.New("CNAME 记录内容必须是有效主机名")
		}
	default:
		return errors.New("仅支持 A、AAAA 或 CNAME 记录")
	}
	return nil
}

func isLoopbackAddress(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
