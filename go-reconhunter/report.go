package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func writeReport(result *ScanResult, outputJSON string, outputHTML string) error {
	if outputJSON != "" {
		if err := os.MkdirAll(filepath.Dir(outputJSON), 0o755); err != nil {
			return err
		}
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(outputJSON, data, 0o644); err != nil {
			return err
		}
		fmt.Printf("JSON report written to %s\n", outputJSON)
	}

	if outputHTML != "" {
		if err := os.MkdirAll(filepath.Dir(outputHTML), 0o755); err != nil {
			return err
		}
		html := renderHTML(result)
		if err := os.WriteFile(outputHTML, []byte(html), 0o644); err != nil {
			return err
		}
		fmt.Printf("HTML report written to %s\n", outputHTML)
	}
	return nil
}

func renderHTML(result *ScanResult) string {
	sort.Slice(result.Triage, func(i, j int) bool {
		return priorityRank(result.Triage[i].Priority) < priorityRank(result.Triage[j].Priority)
	})

	rows := ""
	for _, item := range result.Triage {
		rows += fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td></tr>", item.Priority, item.Title, item.Details)
	}

	reportRows := ""
	for _, note := range result.Reports {
		reportRows += fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>", note.Severity, note.Title, note.Summary, note.Evidence)
	}

	return fmt.Sprintf(`<!doctype html>
<html>
<head><meta charset="utf-8"><title>TWReconHunter Report</title></head>
<body>
  <h1>TWReconHunter Report</h1>
  <p><strong>Target:</strong> %s</p>
  <p><strong>Status:</strong> %d</p>
  <h2>Manual Triage</h2>
  <table>
    <tr><th>Priority</th><th>Title</th><th>Details</th></tr>
    %s
  </table>
  <h2>Detailed Report Notes</h2>
  <table>
    <tr><th>Severity</th><th>Title</th><th>Summary</th><th>Evidence</th></tr>
    %s
  </table>
</body>
</html>`, result.Target, result.StatusCode, rows, reportRows)
}

func priorityRank(priority string) int {
	switch priority {
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

func sendWebhookAlerts(result *ScanResult, discordURL string, telegramConfig string) {
	// Look for high priority findings
	var highFindings []string
	for _, finding := range result.Findings {
		if strings.ToLower(finding.Severity) == "high" || strings.ToLower(finding.Severity) == "critical" {
			highFindings = append(highFindings, fmt.Sprintf("[%s] %s", finding.Severity, finding.Title))
		}
	}
	
	// Also check ActiveScan findings if we modify it to support that (but we are currently passing *ScanResult, not ActiveScanResult)
	// We'll just alert if there are any high findings in the passive scan for now.
	
	if len(highFindings) == 0 {
		return
	}

	message := fmt.Sprintf("TWReconHunter found %d high severity issues on %s\n%s", len(highFindings), result.Target, strings.Join(highFindings, "\n"))

	// Discord Webhook
	if discordURL != "" {
		payload := map[string]string{"content": message}
		data, _ := json.Marshal(payload)
		resp, err := http.Post(discordURL, "application/json", strings.NewReader(string(data)))
		if err == nil {
			resp.Body.Close()
		}
	}

	// Telegram Webhook
	if telegramConfig != "" {
		parts := strings.Split(telegramConfig, ":")
		if len(parts) >= 2 {
			token := parts[0]
			chatID := parts[1]
			urlStr := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
			payload := map[string]string{
				"chat_id": chatID,
				"text":    message,
			}
			data, _ := json.Marshal(payload)
			resp, err := http.Post(urlStr, "application/json", strings.NewReader(string(data)))
			if err == nil {
				resp.Body.Close()
			}
		}
	}
}
