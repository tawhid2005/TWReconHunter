package main

import (
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

	result.Discovered = extractLinks(body, opts.Target)
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

	// CORS Check
	corsReq, err := http.NewRequest(http.MethodOptions, opts.Target, nil)
	if err == nil {
		corsReq.Header.Set("Origin", "https://evil.com")
		if corsResp, err := client.Do(corsReq); err == nil {
			if corsResp.Header.Get("Access-Control-Allow-Origin") == "https://evil.com" {
				result.Findings = append(result.Findings, ActiveFinding{
					Severity: "P2", 
					Title:    "CORS Misconfiguration detected", 
					Detail:   "The server reflects arbitrary Origins in the Access-Control-Allow-Origin header.", 
					URL:      opts.Target, 
					Evidence: "Access-Control-Allow-Origin: https://evil.com",
				})
			}
			corsResp.Body.Close()
		}
	}

	// Subdomain Takeover Scanner
	takeoverFindings := checkSubdomainTakeover(client, result.Subdomains, opts.Target)
	result.Findings = append(result.Findings, takeoverFindings...)

	// Targeted Directory Fuzzing
	fuzzFindings := fuzzSensitiveDirectories(client, opts.Target)
	result.Findings = append(result.Findings, fuzzFindings...)

	// Parameter Discovery
	paramFindings := fuzzHiddenParameters(client, result.Candidates)
	result.Findings = append(result.Findings, paramFindings...)

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
	isAdmin := strings.Contains(lower, "/admin")
	isParameterized := strings.Contains(lower, "id=") || strings.Contains(lower, "?") || strings.Contains(lower, "&") || regexp.MustCompile(`/\d+(?:/|$)`).MatchString(lower)
	switch {
	case isAdmin && isParameterized:
		return "P1"
	case isAdmin:
		return "P2"
	case strings.Contains(lower, "/login") || strings.Contains(lower, "/forgot") || strings.Contains(lower, "/reset"):
		return "P2"
	case strings.Contains(lower, "/upload") || strings.Contains(lower, "/api"):
		return "P3"
	default:
		return "P4"
	}
}

func extractLinks(body string, baseURL string) []string {
	linkPattern := regexp.MustCompile(`(?i)href=["']([^"']+)["']|src=["']([^"']+)["']`)
	matches := linkPattern.FindAllStringSubmatch(body, -1)
	var links []string
	seen := map[string]bool{}
	for _, match := range matches {
		for _, candidate := range match[1:] {
			if candidate == "" {
				continue
			}
			resolved := resolveLink(candidate, baseURL)
			if seen[resolved] {
				continue
			}
			seen[resolved] = true
			links = append(links, resolved)
		}
	}
	return links
}

func resolveLink(raw string, baseURL string) string {
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return raw
	}
	if baseURL == "" {
		return raw
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return raw
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return base.ResolveReference(ref).String()
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

func checkSubdomainTakeover(client *http.Client, subdomains []string, mainTarget string) []ActiveFinding {
	var findings []ActiveFinding
	var mu sync.Mutex
	var wg sync.WaitGroup

	signatures := map[string]string{
		"AWS S3":         "The specified bucket does not exist",
		"GitHub Pages":   "There isn't a GitHub Pages site here.",
		"Heroku":         "No such app",
		"Ghost":          "The thing you were looking for is no longer here, or never was",
		"Pantheon":       "The proudly hosted site is missing",
		"Tumblr":         "Whatever you were looking for doesn't currently exist at this address.",
		"WordPress.com":  "Do you want to register",
		"Zendesk":        "Help Center Closed",
	}

	targets := append([]string{mainTarget}, subdomains...)
	targets = uniqueStrings(targets)

	for _, t := range targets {
		target := t
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			target = "https://" + target
		}

		wg.Add(1)
		go func(urlStr string) {
			defer wg.Done()
			resp, err := client.Get(urlStr)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusNotFound {
				bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 10000))
				bodyStr := string(bodyBytes)

				for provider, sig := range signatures {
					if strings.Contains(bodyStr, sig) {
						mu.Lock()
						findings = append(findings, ActiveFinding{
							Severity: "P1",
							Title:    fmt.Sprintf("Potential Subdomain Takeover (%s)", provider),
							Detail:   fmt.Sprintf("The subdomain seems vulnerable to takeover via %s.", provider),
							URL:      urlStr,
							Evidence: fmt.Sprintf("Response matches signature: %s", sig),
						})
						mu.Unlock()
						break
					}
				}
			}
		}(target)
	}

	wg.Wait()
	return findings
}

func fuzzSensitiveDirectories(client *http.Client, baseURL string) []ActiveFinding {
	var findings []ActiveFinding
	var mu sync.Mutex
	var wg sync.WaitGroup

	parsed, err := url.Parse(baseURL)
	if err != nil {
		return findings
	}
	base := parsed.Scheme + "://" + parsed.Host

	targets := map[string]string{
		"/.env":               "=",
		"/.git/config":        "[core]",
		"/server-status":      "Apache Status",
		"/swagger.json":       "swagger",
		"/docker-compose.yml": "version:",
	}

	for path, expectedSig := range targets {
		urlStr := base + path
		wg.Add(1)
		
		go func(urlStr string, expectedSig string) {
			defer wg.Done()
			resp, err := client.Get(urlStr)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 5000))
				bodyStr := string(bodyBytes)

				if expectedSig == "" || strings.Contains(bodyStr, expectedSig) {
					mu.Lock()
					findings = append(findings, ActiveFinding{
						Severity: "P1",
						Title:    "Sensitive File Exposed",
						Detail:   fmt.Sprintf("A highly sensitive file or directory was found exposed at %s.", urlStr),
						URL:      urlStr,
						Evidence: fmt.Sprintf("Status 200 and matches signature '%s'", expectedSig),
					})
					mu.Unlock()
				}
			}
		}(urlStr, expectedSig)
	}

	wg.Wait()
	return findings
}

func fuzzHiddenParameters(client *http.Client, candidates []string) []ActiveFinding {
	var findings []ActiveFinding
	var mu sync.Mutex
	var wg sync.WaitGroup

	commonParams := []string{"debug", "admin", "test", "id", "user_id", "token", "dir", "cmd"}
	fuzzValues := []string{"true", "1", "admin", "../"}

	for _, candidate := range candidates {
		if !isHighValueCandidate(candidate) {
			continue // Only fuzz high value targets to save time
		}
		
		// First, get the baseline
		baseReq, _ := http.NewRequest(http.MethodGet, candidate, nil)
		baseResp, err := client.Do(baseReq)
		if err != nil {
			continue
		}
		baseBody, _ := io.ReadAll(io.LimitReader(baseResp.Body, 10000))
		baseResp.Body.Close()
		baseLen := len(baseBody)
		baseStatus := baseResp.StatusCode

		for _, param := range commonParams {
			for _, val := range fuzzValues {
				wg.Add(1)
				go func(c, p, v string) {
					defer wg.Done()
					u, err := url.Parse(c)
					if err != nil {
						return
					}
					q := u.Query()
					q.Set(p, v)
					u.RawQuery = q.Encode()

					req, _ := http.NewRequest(http.MethodGet, u.String(), nil)
					resp, err := client.Do(req)
					if err != nil {
						return
					}
					defer resp.Body.Close()

					body, _ := io.ReadAll(io.LimitReader(resp.Body, 10000))
					
					// Basic diff check (status change or significant length change)
					if resp.StatusCode != baseStatus || absDiff(len(body), baseLen) > 100 {
						mu.Lock()
						findings = append(findings, ActiveFinding{
							Severity: "P3",
							Title:    "Hidden Parameter Discovered",
							Detail:   fmt.Sprintf("The parameter '%s' changed the response on %s.", p, c),
							URL:      u.String(),
							Evidence: fmt.Sprintf("Base (Status: %d, Len: %d) -> Fuzzed (Status: %d, Len: %d)", baseStatus, baseLen, resp.StatusCode, len(body)),
						})
						mu.Unlock()
					}
				}(candidate, param, val)
			}
		}
	}
	wg.Wait()
	return findings
}

func absDiff(x, y int) int {
	if x < y {
		return y - x
	}
	return x - y
}
