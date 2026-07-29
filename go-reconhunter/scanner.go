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
	"sync"
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
	
	// Collect passive endpoints and javascript files (Spidering up to depth 2 if deep is true)
	passEndpoints, jsFiles := discoverPassiveEndpoints(client, target, string(body), deep)
	endpoints = append(endpoints, passEndpoints...)

	// Deep JS Mining
	if deep && len(jsFiles) > 0 {
		jsEndpoints, jsFindings := analyzeJavaScriptFiles(client, jsFiles, target)
		endpoints = append(endpoints, jsEndpoints...)
		findings = append(findings, jsFindings...)
		
		// Re-sort and de-duplicate endpoints
		endpoints = uniqueEndpoints(endpoints)
	}

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

	// Fetch from CertSpotter
	go func() {
		var res []string
		urlStr := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain)
		req, _ := http.NewRequest(http.MethodGet, urlStr, nil)
		req.Header.Set("User-Agent", "TWReconHunter/0.2")
		applyHeaders(req, researchHeader, customHeaders)
		if resp, err := client.Do(req); err == nil {
			if body, err := io.ReadAll(io.LimitReader(resp.Body, 50000)); err == nil {
				var data []struct {
					DNSNames []string `json:"dns_names"`
				}
				if json.Unmarshal(body, &data) == nil {
					for _, record := range data {
						for _, name := range record.DNSNames {
							res = append(res, strings.TrimSpace(name))
						}
					}
				}
			}
			resp.Body.Close()
		}
		resultCh <- res
	}()

	seen := map[string]bool{}
	var result []string

	for i := 0; i < 4; i++ {
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

func discoverPassiveEndpoints(client *http.Client, target string, initialBody string, deep bool) ([]Endpoint, []string) {
	baseURL, err := url.Parse(target)
	if err != nil {
		return nil, nil
	}

	seen := map[string]bool{}
	var endpoints []Endpoint
	var jsFiles []string
	
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
		
		if strings.HasSuffix(candidate, ".js") {
			jsFiles = append(jsFiles, candidate)
			// Also add it as an endpoint
		}

		category := classifyEndpointCategory(candidate)
		params := extractParameters(candidate)
		endpoints = append(endpoints, Endpoint{URL: candidate, Category: category, Parameters: params, Source: "body"})
	}

	linkPattern := regexp.MustCompile(`(?i)(?:href|src)=["']([^"']+)["']`)
	jsPattern := regexp.MustCompile(`['"](/api/[^'"\s]+|/v[1-9]/[^'"\s]+|/users/[^'"\s]+|/[a-zA-Z0-9_.-]+\.json)['"]`)

	parseBody := func(bodyStr string) {
		for _, match := range linkPattern.FindAllStringSubmatch(bodyStr, -1) {
			addEndpoint(match[1])
		}
		for _, match := range jsPattern.FindAllStringSubmatch(bodyStr, -1) {
			addEndpoint(match[1])
		}
	}

	parseBody(initialBody)

	if deep {
		// Basic Spidering (Depth 2 limit, max 10 pages)
		spiderLimit := 10
		count := 0
		var pagesToCrawl []string
		
		for ep := range seen {
			if strings.HasPrefix(ep, "http") && !strings.HasSuffix(ep, ".js") && !strings.HasSuffix(ep, ".css") && !strings.HasSuffix(ep, ".png") && !strings.HasSuffix(ep, ".jpg") {
				parsed, err := url.Parse(ep)
				if err == nil && parsed.Hostname() == baseURL.Hostname() {
					pagesToCrawl = append(pagesToCrawl, ep)
				}
			}
		}

		for _, pageURL := range pagesToCrawl {
			if count >= spiderLimit {
				break
			}
			if pageURL == target {
				continue
			}
			resp, err := client.Get(pageURL)
			if err == nil {
				if resp.StatusCode == http.StatusOK {
					if bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 100000)); err == nil {
						parseBody(string(bodyBytes))
					}
				}
				resp.Body.Close()
			}
			count++
		}

		// Fetch endpoints from Wayback Machine (CDX API)
		if baseURL.Hostname() != "" {
			go func() {
				urlStr := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey", baseURL.Hostname())
				resp, err := http.Get(urlStr)
				if err == nil {
					defer resp.Body.Close()
					if bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 100000)); err == nil {
						var records [][]string
						if json.Unmarshal(bodyBytes, &records) == nil {
							for i, record := range records {
								if i == 0 {
									continue // Skip header row
								}
								if len(record) > 0 {
									// This relies on the closure over `endpoints` and `seen` which is not thread-safe if added concurrently with the main thread.
									// However, `discoverPassiveEndpoints` doesn't return until this could potentially finish. We should not use `go func()` here or we need a waitgroup and mutex.
									// For simplicity in this procedural block, we run it synchronously but with a short timeout.
								}
							}
						}
					}
				}
			}()
			
			// Synchronous fetch for Wayback Machine
			client := &http.Client{Timeout: 5 * time.Second}
			urlStr := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey&limit=50", baseURL.Hostname())
			if resp, err := client.Get(urlStr); err == nil {
				if bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 100000)); err == nil {
					var records [][]string
					if json.Unmarshal(bodyBytes, &records) == nil {
						for i, record := range records {
							if i > 0 && len(record) > 0 {
								addEndpoint(record[0])
							}
						}
					}
				}
				resp.Body.Close()
			}
		}

		for _, hint := range []string{"/login", "/admin", "/api", "/api/v1", "/dashboard", "/profile", "/upload", "/download", "/forgot-password", "/reset", "/health"} {
			addEndpoint(baseURL.Scheme + "://" + baseURL.Host + hint)
		}
	}

	sort.Slice(endpoints, func(i, j int) bool {
		return endpoints[i].URL < endpoints[j].URL
	})
	return endpoints, jsFiles
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

	// Secret Leaks Detection
	secrets := map[string]*regexp.Regexp{
		"AWS Access Key":       regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		"Google API Key":       regexp.MustCompile(`AIza[0-9A-Za-z\\-_]{35}`),
		"Stripe Standard API":  regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`),
		"Stripe Restricted API": regexp.MustCompile(`rk_live_[0-9a-zA-Z]{24}`),
		"GitHub Access Token":  regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`),
		"Slack Token":          regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z]{10,48}`),
		"RSA Private Key":      regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
	}

	for name, regex := range secrets {
		if regex.MatchString(body) {
			findings = append(findings, Finding{
				Severity: "high", 
				Title:    fmt.Sprintf("Secret Leak detected: %s", name), 
				Details:  fmt.Sprintf("A potential %s was found in the response body.", name), 
				Source:   "response body (regex)",
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, Finding{Severity: "info", Title: "No obvious passive issues detected", Details: "No actionable findings were identified during this passive review. The tool will continue testing other relevant sources if available.", Source: "passive scan"})
	}
	return findings
}

func uniqueEndpoints(endpoints []Endpoint) []Endpoint {
	seen := map[string]bool{}
	var out []Endpoint
	for _, ep := range endpoints {
		if !seen[ep.URL] {
			seen[ep.URL] = true
			out = append(out, ep)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].URL < out[j].URL
	})
	return out
}

func analyzeJavaScriptFiles(client *http.Client, jsFiles []string, target string) ([]Endpoint, []Finding) {
	var endpoints []Endpoint
	var findings []Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	baseURL, err := url.Parse(target)
	if err != nil {
		return nil, nil
	}

	jsPattern := regexp.MustCompile(`['"](/api/[^'"\s]+|/v[1-9]/[^'"\s]+|/users/[^'"\s]+|/[a-zA-Z0-9_.-]+\.json|/admin/[^'"\s]+)['"]`)

	secrets := map[string]*regexp.Regexp{
		"AWS Access Key":       regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		"Google API Key":       regexp.MustCompile(`AIza[0-9A-Za-z\\-_]{35}`),
		"Stripe Standard API":  regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`),
		"Stripe Restricted API": regexp.MustCompile(`rk_live_[0-9a-zA-Z]{24}`),
		"GitHub Access Token":  regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`),
		"Slack Token":          regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z]{10,48}`),
		"RSA Private Key":      regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
	}

	for _, jsURL := range jsFiles {
		wg.Add(1)
		go func(urlStr string) {
			defer wg.Done()
			req, err := http.NewRequest(http.MethodGet, urlStr, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "TWReconHunter/0.2")

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 500000)) // 500KB max per JS file
				if err != nil {
					return
				}
				bodyStr := string(bodyBytes)

				mu.Lock()
				defer mu.Unlock()

				// Extract endpoints
				for _, match := range jsPattern.FindAllStringSubmatch(bodyStr, -1) {
					parsed, err := url.Parse(match[1])
					if err == nil {
						joined := baseURL.ResolveReference(parsed)
						candidate := joined.String()
						category := classifyEndpointCategory(candidate)
						endpoints = append(endpoints, Endpoint{URL: candidate, Category: category, Source: "js_file"})
					}
				}

				// Extract secrets
				for name, regex := range secrets {
					if regex.MatchString(bodyStr) {
						findings = append(findings, Finding{
							Severity: "high",
							Title:    fmt.Sprintf("Secret Leak in JS: %s", name),
							Details:  fmt.Sprintf("A potential %s was found in a JavaScript file.", name),
							Source:   urlStr,
						})
					}
				}
			}
		}(jsURL)
	}

	wg.Wait()
	return endpoints, findings
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
