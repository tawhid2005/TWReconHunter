package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

type ActiveFinding struct {
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	URL      string `json:"url"`
	Evidence string `json:"evidence"`
}

type ActiveScanResult struct {
	Target     string          `json:"target"`
	Findings   []ActiveFinding `json:"findings"`
	Discovered []string        `json:"discovered"`
	Subdomains []string        `json:"subdomains"`
	Params     []string        `json:"params"`
	Candidates []string        `json:"candidates"`
}

type ActiveScanOptions struct {
	Target string
	Depth  int
}

func runActiveScan(opts ActiveScanOptions) (*ActiveScanResult, error) {
	client := &http.Client{Timeout: 8 * time.Second}
	result := &ActiveScanResult{Target: opts.Target}

	req, err := http.NewRequest(http.MethodGet, opts.Target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "TWReconHunter-Active/0.1")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 20000))
	if err != nil {
		return nil, err
	}
	body := string(bodyBytes)

	result.Discovered = extractLinks(body)
	result.Subdomains = discoverSubdomainHints(opts.Target)
	for _, link := range result.Discovered {
		result.Params = append(result.Params, extractQueryParams(link)...)
	}
	result.Params = uniqueStrings(result.Params)
	result.Candidates = buildCandidateList(result.Discovered, result.Subdomains, opts.Target)

	if detectOpenRedirect(resp.Header, resp.StatusCode) {
		result.Findings = append(result.Findings, ActiveFinding{Severity: "P3", Title: "Open redirect possible", Detail: "The response appears to redirect to an external domain, which is worth manual review for open redirect issues.", URL: opts.Target, Evidence: fmt.Sprintf("status=%d location=%s", resp.StatusCode, resp.Header.Get("Location"))})
	}

	if strings.Contains(strings.ToLower(body), "<script") || strings.Contains(strings.ToLower(body), "alert(") {
		result.Findings = append(result.Findings, ActiveFinding{Severity: "P3", Title: "HTML reflected content detected", Detail: "The page body contains script-like content, which is a signpost for reflected XSS review.", URL: opts.Target, Evidence: "script-like content present in response body"})
	}

	if strings.Contains(strings.ToLower(body), "server") && strings.Contains(strings.ToLower(body), "error") {
		result.Findings = append(result.Findings, ActiveFinding{Severity: "P4", Title: "Verbose error output detected", Detail: "The response appears to contain verbose error output that may leak implementation details.", URL: opts.Target, Evidence: "error-like content present in response body"})
	}

	for _, candidate := range result.Candidates {
		if isHighValueCandidate(candidate) {
			result.Findings = append(result.Findings, ActiveFinding{Severity: prioritizeCandidate(candidate), Title: "High-value review surface", Detail: fmt.Sprintf("This candidate looks like a strong bug bounty target: %s", candidate), URL: candidate, Evidence: "heuristic candidate scoring"})
		}
	}

	sort.Slice(result.Findings, func(i, j int) bool {
		return severityRank(result.Findings[i].Severity) < severityRank(result.Findings[j].Severity)
	})
	return result, nil
}

func discoverSubdomainHints(target string) []string {
	parsed, err := url.Parse(target)
	if err != nil {
		return nil
	}
	host := parsed.Hostname()
	if host == "" {
		return nil
	}
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return nil
	}
	domain := strings.Join(parts[len(parts)-2:], ".")
	hints := []string{fmt.Sprintf("www.%s", domain), fmt.Sprintf("app.%s", domain), fmt.Sprintf("admin.%s", domain), fmt.Sprintf("login.%s", domain)}
	return uniqueStrings(hints)
}

func buildCandidateList(discovered []string, subdomains []string, target string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			return
		}
		seen[value] = true
		out = append(out, value)
	}
	for _, item := range discovered {
		add(item)
	}
	for _, item := range subdomains {
		add(item)
	}
	add(target)
	return out
}

func isHighValueCandidate(candidate string) bool {
	lower := strings.ToLower(candidate)
	return strings.Contains(lower, "/admin") || strings.Contains(lower, "/login") || strings.Contains(lower, "/upload") || strings.Contains(lower, "/api") || strings.Contains(lower, "/forgot") || strings.Contains(lower, "/reset") || strings.Contains(lower, "/download") || strings.Contains(lower, "/profile")
}

func prioritizeCandidate(candidate string) string {
	lower := strings.ToLower(candidate)
	switch {
	case strings.Contains(lower, "/admin"):
		return "P2"
	case strings.Contains(lower, "/login") || strings.Contains(lower, "/forgot") || strings.Contains(lower, "/reset"):
		return "P3"
	case strings.Contains(lower, "/upload") || strings.Contains(lower, "/api"):
		return "P3"
	default:
		return "P4"
	}
}

func extractLinks(body string) []string {
	linkPattern := regexp.MustCompile(`(?i)href=["']([^"']+)["']|src=["']([^"']+)["']`)
	matches := linkPattern.FindAllStringSubmatch(body, -1)
	var links []string
	seen := map[string]bool{}
	for _, match := range matches {
		for _, candidate := range match[1:] {
			if candidate == "" {
				continue
			}
			if seen[candidate] {
				continue
			}
			seen[candidate] = true
			links = append(links, candidate)
		}
	}
	return links
}

func extractQueryParams(raw string) []string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	if len(parsed.Query()) == 0 {
		return nil
	}
	params := make([]string, 0, len(parsed.Query()))
	for key := range parsed.Query() {
		params = append(params, key)
	}
	sort.Strings(params)
	return params
}

func detectOpenRedirect(headers http.Header, status int) bool {
	if status != http.StatusFound && status != http.StatusMovedPermanently && status != http.StatusTemporaryRedirect && status != http.StatusPermanentRedirect {
		return false
	}
	location := headers.Get("Location")
	if location == "" {
		return false
	}
	return strings.Contains(strings.ToLower(location), "http://") || strings.Contains(strings.ToLower(location), "https://")
}

func severityRank(level string) int {
	switch strings.ToUpper(level) {
	case "P1":
		return 1
	case "P2":
		return 2
	case "P3":
		return 3
	case "P4":
		return 4
	default:
		return 5
	}
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}
