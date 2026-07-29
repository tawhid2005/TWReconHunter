package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

type ScanResult struct {
	Target      string            `json:"target"`
	StatusCode  int               `json:"status_code"`
	Headers     map[string]string `json:"headers"`
	BodySnippet string            `json:"body_snippet"`
	Subdomains  []string          `json:"subdomains"`
	Findings    []Finding         `json:"findings"`
	Endpoints   []Endpoint        `json:"endpoints"`
	Triage      []TriageFinding   `json:"triage"`
	Reports     []ReportNote      `json:"reports"`
}

type Finding struct {
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Details  string `json:"details"`
	Source   string `json:"source"`
}

type ReproStep struct {
	Step     string `json:"step"`
	Action   string `json:"action"`
	Expected string `json:"expected"`
	Observed string `json:"observed"`
}

type ReportNote struct {
	Title      string      `json:"title"`
	Summary    string      `json:"summary"`
	Severity   string      `json:"severity"`
	Evidence   string      `json:"evidence"`
	ReproSteps []ReproStep `json:"repro_steps"`
}

type Endpoint struct {
	URL        string   `json:"url"`
	Category   string   `json:"category"`
	Parameters []string `json:"parameters,omitempty"`
	Source     string   `json:"source,omitempty"`
}

func runScan(target string, scopeDomain string) (*ScanResult, error) {
	return runScanWithOptions(target, scopeDomain, "", nil, false)
}

func runScanWithResearchHeader(target string, scopeDomain string, researchHeader string) (*ScanResult, error) {
	return runScanWithOptions(target, scopeDomain, researchHeader, nil, false)
}

func runScanWithOptions(target string, scopeDomain string, researchHeader string, customHeaders []string, deep bool) (*ScanResult, error) {
	client := &http.Client{Timeout: 8 * time.Second}
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "TWReconHunter/0.2")
	applyHeaders(req, researchHeader, customHeaders)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	headers := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 12000))
	if err != nil {
		return nil, err
	}

	domain := extractDomain(target)
	subdomains := discoverSubdomains(client, domain, researchHeader, customHeaders)
	findings := buildFindings(headers, string(body))
	endpoints := []Endpoint{{URL: target, Category: classifyEndpointCategory(target), Source: "root"}}
	endpoints = append(endpoints, discoverPassiveEndpoints(target, string(body), deep)...)
	triage := buildTriageFindings(endpoints, string(body))
	reports := buildReports(findings, triage, target)

	return &ScanResult{
		Target:      target,
		StatusCode:  resp.StatusCode,
		Headers:     headers,
		BodySnippet: fmt.Sprintf("Status %d from %s", resp.StatusCode, target),
		Subdomains:  subdomains,
		Findings:    findings,
		Endpoints:   endpoints,
		Triage:      triage,
		Reports:     reports,
	}, nil
}

func applyHeaders(req *http.Request, researchHeader string, customHeaders []string) {
	if strings.TrimSpace(researchHeader) != "" {
		req.Header.Set("X-HackerOne-Research", strings.TrimSpace(researchHeader))
	}
	for _, h := range customHeaders {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
}

func applyResearchHeader(req *http.Request, researchHeader string) {
	if strings.TrimSpace(researchHeader) == "" {
		return
	}
	req.Header.Set("X-HackerOne-Research", strings.TrimSpace(researchHeader))
}

func extractDomain(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return strings.TrimPrefix(strings.TrimPrefix(raw, "https://"), "http://")
	}
	host := parsed.Hostname()
	if host == "" {
		return strings.TrimPrefix(strings.TrimPrefix(raw, "https://"), "http://")
	}
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return host
}

func discoverSubdomains(client *http.Client, domain string, researchHeader string, customHeaders []string) []string {
	if domain == "" {
		return nil
	}

	resultCh := make(chan []string, 3)

	// Fetch from crt.sh
	go func() {
		var res []string
		urlStr := fmt.Sprintf("https://crt.sh/?q=%%%s&output=json", domain)
		req, _ := http.NewRequest(http.MethodGet, urlStr, nil)
		req.Header.Set("User-Agent", "TWReconHunter/0.2")
		applyHeaders(req, researchHeader, customHeaders)
		if resp, err := client.Do(req); err == nil {
			if body, err := io.ReadAll(io.LimitReader(resp.Body, 50000)); err == nil {
				var records []map[string]any
				if json.Unmarshal(body, &records) == nil {
					for _, record := range records {
						if nameValue, ok := record["name_value"].(string); ok {
							for _, part := range strings.Split(nameValue, "\n") {
								res = append(res, strings.TrimSpace(part))
							}
						}
					}
				}
			}
			resp.Body.Close()
		}
		resultCh <- res
	}()

	// Fetch from HackerTarget
	go func() {
		var res []string
		urlStr := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
		req, _ := http.NewRequest(http.MethodGet, urlStr, nil)
		req.Header.Set("User-Agent", "TWReconHunter/0.2")
		applyHeaders(req, researchHeader, customHeaders)
		if resp, err := client.Do(req); err == nil {
			if body, err := io.ReadAll(io.LimitReader(resp.Body, 50000)); err == nil {
				text := string(body)
				if !strings.Contains(strings.ToLower(text), "error") {
					for _, line := range strings.Split(text, "\n") {
						parts := strings.Split(line, ",")
						if len(parts) > 0 {
							res = append(res, strings.TrimSpace(parts[0]))
						}
					}
				}
			}
			resp.Body.Close()
		}
		resultCh <- res
	}()

	// Fetch from AlienVault OTX
	go func() {
		var res []string
		urlStr := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)
		req, _ := http.NewRequest(http.MethodGet, urlStr, nil)
		req.Header.Set("User-Agent", "TWReconHunter/0.2")
		applyHeaders(req, researchHeader, customHeaders)
		if resp, err := client.Do(req); err == nil {
			if body, err := io.ReadAll(io.LimitReader(resp.Body, 50000)); err == nil {
				var data struct {
					PassiveDNS []struct {
						Hostname string `json:"hostname"`
					} `json:"passive_dns"`
				}
				if json.Unmarshal(body, &data) == nil {
					for _, record := range data.PassiveDNS {
						res = append(res, strings.TrimSpace(record.Hostname))
					}
				}
			}
			resp.Body.Close()
		}
		resultCh <- res
	}()

	seen := map[string]bool{}
	var result []string

	for i := 0; i < 3; i++ {
		names := <-resultCh
		for _, clean := range names {
			if clean == "" {
				continue
			}
			if strings.HasSuffix(clean, "."+domain) || clean == domain {
				if !seen[clean] {
					seen[clean] = true
					result = append(result, clean)
				}
			}
		}
	}

	if len(result) > 50 {
		return result[:50]
	}
	return result
}

func discoverPassiveEndpoints(target string, body string, deep bool) []Endpoint {
	baseURL, err := url.Parse(target)
	if err != nil {
		return nil
	}

	seen := map[string]bool{}
	var endpoints []Endpoint
	addEndpoint := func(raw string) {
		candidate := strings.TrimSpace(raw)
		if candidate == "" || strings.HasPrefix(candidate, "mailto:") || strings.HasPrefix(candidate, "javascript:") || strings.HasPrefix(candidate, "#") {
			return
		}
		parsed, err := url.Parse(candidate)
		if err != nil {
			return
		}
		if parsed.IsAbs() {
			if parsed.Hostname() != baseURL.Hostname() {
				return
			}
			candidate = parsed.String()
		} else {
			if parsed.Path == "" {
				return
			}
			joined := baseURL.ResolveReference(parsed)
			candidate = joined.String()
		}
		if seen[candidate] {
			return
		}
		seen[candidate] = true
		category := classifyEndpointCategory(candidate)
		params := extractParameters(candidate)
		endpoints = append(endpoints, Endpoint{URL: candidate, Category: category, Parameters: params, Source: "body"})
	}

	linkPattern := regexp.MustCompile(`(?i)(?:href|src)=["']([^"']+)["']`)
	for _, match := range linkPattern.FindAllStringSubmatch(body, -1) {
		addEndpoint(match[1])
	}

	// JS Endpoint Extraction
	jsPattern := regexp.MustCompile(`['"](/api/[^'"\s]+|/v[1-9]/[^'"\s]+|/users/[^'"\s]+|/[a-zA-Z0-9_.-]+\.json)['"]`)
	for _, match := range jsPattern.FindAllStringSubmatch(body, -1) {
		addEndpoint(match[1])
	}

	if deep {
		for _, hint := range []string{"/login", "/admin", "/api", "/api/v1", "/dashboard", "/profile", "/upload", "/download", "/forgot-password", "/reset", "/health"} {
			addEndpoint(baseURL.Scheme + "://" + baseURL.Host + hint)
		}
	}

	sort.Slice(endpoints, func(i, j int) bool {
		return endpoints[i].URL < endpoints[j].URL
	})
	return endpoints
}

func extractParameters(raw string) []string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	values := parsed.Query()
	if len(values) == 0 {
		return nil
	}
	params := make([]string, 0, len(values))
	for key := range values {
		params = append(params, key)
	}
	sort.Strings(params)
	return params
}

func buildFindings(headers map[string]string, body string) []Finding {
	findings := []Finding{}
	lowerBody := strings.ToLower(body)
	for _, header := range []string{"strict-transport-security", "content-security-policy", "x-frame-options"} {
		if strings.ToLower(headers[header]) == "" {
			findings = append(findings, Finding{Severity: "medium", Title: fmt.Sprintf("Missing %s", header), Details: fmt.Sprintf("The response does not include %s.", header), Source: "response header"})
		}
	}
	if strings.Contains(lowerBody, "index of /") || strings.Contains(lowerBody, "directory listing") {
		findings = append(findings, Finding{Severity: "medium", Title: "Directory listing enabled", Details: "The server appears to expose directory contents.", Source: "response body"})
	}
	if strings.Contains(lowerBody, "exception") || strings.Contains(lowerBody, "traceback") || strings.Contains(lowerBody, "stack trace") {
		findings = append(findings, Finding{Severity: "low", Title: "Verbose error leak", Details: "The response body exposes error details.", Source: "response body"})
	}
	if len(findings) == 0 {
		findings = append(findings, Finding{Severity: "info", Title: "No obvious passive issues detected", Details: "No actionable findings were identified during this passive review. The tool will continue testing other relevant sources if available.", Source: "passive scan"})
	}
	return findings
}

func classifyEndpointCategory(raw string) string {
	lower := strings.ToLower(raw)
	switch {
	case strings.Contains(lower, "/login") || strings.Contains(lower, "/auth"):
		return "auth"
	case strings.Contains(lower, "/admin"):
		return "admin"
	case strings.Contains(lower, "/upload") || strings.Contains(lower, "/file"):
		return "file"
	case strings.Contains(lower, "/api"):
		return "api"
	default:
		return "general"
	}
}
