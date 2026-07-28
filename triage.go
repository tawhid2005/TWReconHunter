package main

import (
	"fmt"
	"strings"
)

type TriageFinding struct {
	Priority string `json:"priority"`
	Title    string `json:"title"`
	Details  string `json:"details"`
	URL      string `json:"url,omitempty"`
}

func buildTriageFindings(endpoints []Endpoint, body string) []TriageFinding {
	findings := []TriageFinding{}
	lowerBody := strings.ToLower(body)

	for _, endpoint := range endpoints {
		score := 0
		title := "Manual review candidate"
		details := "Review this endpoint for auth, IDOR, or access control issues."
		url := endpoint.URL
		lowerURL := strings.ToLower(url)

		switch endpoint.Category {
		case "auth":
			score += 4
			title = "Authentication-related surface"
			details = "Authentication and login flows are strong candidates for access-control review."
		case "admin":
			score += 5
			title = "Admin-related surface"
			details = "Admin paths often expose sensitive functionality and should be reviewed first."
		case "file":
			score += 4
			title = "File upload or file handling surface"
			details = "File handling endpoints can lead to stored XSS, path traversal, or abuse scenarios."
		case "api":
			score += 3
			title = "API endpoint"
			details = "API endpoints often expose internal logic and parameter handling issues."
		}

		for _, param := range endpoint.Parameters {
			if strings.Contains(param, "id") || strings.Contains(param, "user") || strings.Contains(param, "order") || strings.Contains(param, "token") || strings.Contains(param, "session") {
				score += 2
			}
		}

		if strings.Contains(lowerURL, "reset") || strings.Contains(lowerURL, "forgot") || strings.Contains(lowerURL, "password") {
			score += 3
		}
		if strings.Contains(lowerURL, "download") || strings.Contains(lowerURL, "upload") || strings.Contains(lowerURL, "export") {
			score += 2
		}
		if strings.Contains(lowerURL, "admin") || strings.Contains(lowerURL, "dashboard") || strings.Contains(lowerURL, "profile") {
			score += 2
		}

		if strings.Contains(lowerBody, "login") || strings.Contains(lowerBody, "signin") || strings.Contains(lowerBody, "forgot password") || strings.Contains(lowerBody, "password") {
			score += 3
		}
		if strings.Contains(lowerBody, "admin") || strings.Contains(lowerBody, "dashboard") {
			score += 3
		}
		if strings.Contains(lowerBody, "upload") || strings.Contains(lowerBody, "file") {
			score += 2
		}
		if strings.Contains(lowerBody, "swagger") || strings.Contains(lowerBody, "/api/") || strings.Contains(lowerBody, "openapi") {
			score += 2
		}

		priority := mapPriority(score)
		if priority != "P5" {
			findings = append(findings, TriageFinding{Priority: priority, Title: title, Details: details, URL: url})
		}
	}

	return findings
}

func mapPriority(score int) string {
	switch {
	case score >= 10:
		return "P1"
	case score >= 8:
		return "P2"
	case score >= 6:
		return "P3"
	case score >= 4:
		return "P4"
	default:
		return "P5"
	}
}

func buildParameterHints(endpoint Endpoint) []string {
	hints := []string{}
	for _, param := range endpoint.Parameters {
		if strings.Contains(param, "id") || strings.Contains(param, "user") || strings.Contains(param, "order") || strings.Contains(param, "token") || strings.Contains(param, "session") {
			hints = append(hints, fmt.Sprintf("parameter '%s' is a strong IDOR/auth review candidate", param))
		}
	}
	return hints
}

func buildReports(findings []Finding, triage []TriageFinding, target string) []ReportNote {
	reports := []ReportNote{}
	if len(findings) == 0 && len(triage) == 0 {
		reports = append(reports, ReportNote{
			Title:    "No actionable findings identified",
			Summary:  "The passive review did not surface a clear actionable issue during this scan.",
			Severity: "Info",
			Evidence: fmt.Sprintf("Target: %s", target),
			ReproSteps: []ReproStep{{
				Step:     "1",
				Action:   "Review the scan output and export files.",
				Expected: "The tool should clearly indicate that no actionable issue was identified.",
				Observed: "The scan completed and reported that no obvious passive issues were detected.",
			}},
		})
		return reports
	}

	for _, item := range triage {
		reports = append(reports, ReportNote{
			Title:    item.Title,
			Summary:  item.Details,
			Severity: item.Priority,
			Evidence: item.URL,
			ReproSteps: []ReproStep{{
				Step:     "1",
				Action:   fmt.Sprintf("Open the suspected endpoint: %s", item.URL),
				Expected: "The endpoint should be relevant to a sensitive workflow such as auth, admin, or file handling.",
				Observed: item.Details,
			}, {
				Step:     "2",
				Action:   "Inspect parameters and surrounding application behavior.",
				Expected: "The endpoint should reveal a manual review candidate for authorization, parameter abuse, or business logic issues.",
				Observed: "Manual triage should continue from this report entry.",
			}},
		})
	}
	return reports
}
