package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
}

type Finding struct {
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Details  string `json:"details"`
}

type Endpoint struct {
	URL        string   `json:"url"`
	Category   string   `json:"category"`
	Parameters []string `json:"parameters,omitempty"`
}

func runScan(target string, scopeDomain string) (*ScanResult, error) {
	client := &http.Client{Timeout: 8 * time.Second}
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "TWReconHunter/0.1")

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
	subdomains := discoverSubdomains(client, domain)
	findings := buildFindings(headers, string(body))
	endpoints := []Endpoint{{URL: target, Category: classifyEndpointCategory(target)}}

	return &ScanResult{
		Target:      target,
		StatusCode:  resp.StatusCode,
		Headers:     headers,
		BodySnippet: fmt.Sprintf("Status %d from %s", resp.StatusCode, target),
		Subdomains:  subdomains,
		Findings:    findings,
		Endpoints:   endpoints,
	}, nil
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

func discoverSubdomains(client *http.Client, domain string) []string {
	if domain == "" {
		return nil
	}
	urlStr := fmt.Sprintf("https://crt.sh/?q=%%%s&output=json", domain)
	req, _ := http.NewRequest(http.MethodGet, urlStr, nil)
	req.Header.Set("User-Agent", "TWReconHunter/0.1")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 20000))
	if err != nil {
		return nil
	}

	var records []map[string]any
	if err := json.Unmarshal(body, &records); err != nil {
		return nil
	}

	seen := map[string]bool{}
	var result []string
	for _, record := range records {
		if nameValue, ok := record["name_value"].(string); ok {
			for _, part := range strings.Split(nameValue, "\n") {
				clean := strings.TrimSpace(part)
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
	}
	return result
}

func buildFindings(headers map[string]string, body string) []Finding {
	findings := []Finding{}
	lowerBody := strings.ToLower(body)
	for _, header := range []string{"strict-transport-security", "content-security-policy", "x-frame-options"} {
		if strings.ToLower(headers[header]) == "" {
			findings = append(findings, Finding{Severity: "medium", Title: fmt.Sprintf("Missing %s", header), Details: fmt.Sprintf("The response does not include %s.", header)})
		}
	}
	if strings.Contains(lowerBody, "index of /") || strings.Contains(lowerBody, "directory listing") {
		findings = append(findings, Finding{Severity: "medium", Title: "Directory listing enabled", Details: "The server appears to expose directory contents."})
	}
	if strings.Contains(lowerBody, "exception") || strings.Contains(lowerBody, "traceback") || strings.Contains(lowerBody, "stack trace") {
		findings = append(findings, Finding{Severity: "low", Title: "Verbose error leak", Details: "The response body exposes error details."})
	}
	if len(findings) == 0 {
		findings = append(findings, Finding{Severity: "info", Title: "No obvious passive issues detected", Details: "Only passive checks were run."})
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
