package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

func main() {
	var target string
	var confirmScope bool
	var scopeDomain string
	var outputJSON string
	var outputHTML string
	var researchHeader string
	var deepMode bool
	var customHeaders []string
	var discordWebhook string
	var telegramWebhook string

	rootCmd := &cobra.Command{
		Use:   "twreconhunter",
		Short: "Passive recon and manual review assistant",
		Long: `TWReconHunter is a passive reconnaissance and manual review assistant for authorized security testing.

How it works:
  1. Accept a target URL or domain.
  2. Confirm the target is in scope.
  3. Discover candidate links, parameters, and likely subdomain hints.
  4. Score the most interesting bug bounty surfaces automatically.
  5. Produce actionable triage suggestions and export JSON or HTML reports.

Common usage:
  twreconhunter active -u https://example.com --confirm-scope
  twreconhunter -u https://example.com --confirm-scope
  twreconhunter --url https://example.com --confirm-scope --scope-domain example.com
  twreconhunter -u https://example.com --confirm-scope --research-header your-h1-username
  twreconhunter -u https://example.com --confirm-scope --deep
  twreconhunter -u https://example.com --confirm-scope --output-json reports/example.json --output-html reports/example.html
  twreconhunter update

Important notes:
  - This tool is passive only. It does not send exploit payloads.
  - It is intended for authorized testing and responsible research.
  - Use --research-header only when you have a legitimate reason to identify your testing context.
  - Use --deep to add passive endpoint heuristics from page links and common sensitive paths.
  - Use the active subcommand for a one-shot recon-to-triage workflow.
`,
		Example: `  twreconhunter active -u https://example.com --confirm-scope
  twreconhunter -u https://example.com --confirm-scope --research-header your-h1-username
  twreconhunter update`,
	}

	rootCmd.RunE = func(cmd *cobra.Command, args []string) error {
		if target == "" {
			return fmt.Errorf("target URL is required")
		}

		if !confirmScope {
			fmt.Println("Error: You must provide --confirm-scope to confirm the target is authorized.")
			os.Exit(1)
		}

		fmt.Printf("Starting passive scan against: %s\n", target)
		if len(customHeaders) > 0 {
			fmt.Printf("Using %d custom headers\n", len(customHeaders))
		}
		if deepMode {
			fmt.Println("Deep passive enumeration enabled.")
		}

		result, err := runScanWithOptions(target, scopeDomain, researchHeader, customHeaders, deepMode)
		if err != nil {
			fmt.Printf("Error scanning target: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Status: %d\n", result.StatusCode)
		fmt.Printf("Headers: %d\n", len(result.Headers))
		fmt.Println("\n[Subdomains]")
		if len(result.Subdomains) == 0 {
			fmt.Println("- No subdomains discovered from passive sources")
		} else {
			for _, sub := range result.Subdomains {
				fmt.Printf("- %s\n", sub)
			}
		}
		fmt.Println("\n[Findings]")
		for _, finding := range result.Findings {
			fmt.Printf("[%s] %s - %s\n", strings.ToUpper(finding.Severity), finding.Title, finding.Details)
		}
		fmt.Println("\n[Endpoints]")
		for _, endpoint := range result.Endpoints {
			fmt.Printf("- %s [%s]\n", endpoint.URL, endpoint.Category)
		}
		fmt.Println("\n[Manual Triage]")
		if len(result.Triage) == 0 {
			fmt.Println("- No high-priority manual review candidates detected")
		} else {
			for _, item := range result.Triage {
				fmt.Printf("[%s] %s - %s\n", item.Priority, item.Title, item.Details)
				if item.URL != "" {
					fmt.Printf("    URL: %s\n", item.URL)
				}
			}
		}
		if err := writeReport(result, outputJSON, outputHTML); err != nil {
			return err
		}
		
		if discordWebhook != "" || telegramWebhook != "" {
			sendWebhookAlerts(result, discordWebhook, telegramWebhook)
		}
		
		fmt.Println("\nPassive scan completed.")
		return nil
	}

	var update bool
	activeCmd := &cobra.Command{
		Use:     "active",
		Short:   "Run the active MVP scanner against a target",
		Long:    "Run an initial active scan that discovers links and parameters, then checks a small set of high-signal bug classes such as open redirect and reflected content.",
		Example: `  twreconhunter active -u https://example.com`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if target == "" {
				return fmt.Errorf("target URL is required")
			}
			if !confirmScope {
				return fmt.Errorf("you must provide --confirm-scope before running active checks")
			}
			fmt.Println("Warning: this active mode sends test requests and should only be used on authorized targets.")
			result, err := runActiveScan(ActiveScanOptions{Target: target, Depth: 1})
			if err != nil {
				return err
			}
			fmt.Printf("Active scan results for %s\n", result.Target)
			fmt.Printf("Discovered links: %d\n", len(result.Discovered))
			fmt.Printf("Parameters: %s\n", strings.Join(result.Params, ", "))
			if len(result.Findings) == 0 {
				fmt.Println("No findings from the initial active checks")
				return nil
			}
			fmt.Println("Findings:")
			for _, finding := range result.Findings {
				fmt.Printf("[%s] %s - %s\n", finding.Severity, finding.Title, finding.Detail)
			}
			return nil
		},
	}
	activeCmd.Flags().StringVarP(&target, "url", "u", "", "Target URL to scan")
	activeCmd.Flags().BoolVar(&confirmScope, "confirm-scope", false, "Confirm that the target is authorized for testing")
	rootCmd.AddCommand(activeCmd)

	rootCmd.AddCommand(&cobra.Command{
		Use:     "update",
		Short:   "Download the latest binary from GitHub",
		Long:    "Download and install the latest release binary for this platform.",
		Example: `  twreconhunter update`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUpdate()
		},
	})

	interactiveCmd := &cobra.Command{
		Use:   "interactive",
		Short: "Run the interactive Terminal UI (TUI) dashboard",
		RunE: func(cmd *cobra.Command, args []string) error {
			if target == "" {
				return fmt.Errorf("target URL (-u) is required for interactive mode")
			}
			if !confirmScope {
				return fmt.Errorf("you must confirm you are authorized to scan this target using --confirm-scope")
			}
			return runTUI(target, deepMode)
		},
	}
	interactiveCmd.Flags().StringVarP(&target, "url", "u", "", "Target URL to scan")
	interactiveCmd.Flags().BoolVar(&confirmScope, "confirm-scope", false, "Confirm that the target is authorized for testing")
	interactiveCmd.Flags().BoolVar(&deepMode, "deep", false, "Enable deep JS mining and spidering")
	rootCmd.AddCommand(interactiveCmd)

	rootCmd.Flags().StringVarP(&target, "url", "u", "", "Target URL or domain")
	rootCmd.Flags().BoolVar(&confirmScope, "confirm-scope", false, "Confirm that the target is authorized for testing")
	rootCmd.Flags().StringVar(&scopeDomain, "scope-domain", "", "Optional in-scope domain")
	rootCmd.Flags().StringVar(&outputJSON, "output-json", "", "Optional path to write a JSON report")
	rootCmd.Flags().StringVar(&outputHTML, "output-html", "", "Optional path to write an HTML report")
	rootCmd.Flags().StringVar(&researchHeader, "research-header", "", "Optional value for X-HackerOne-Research header for authorized testing")
	rootCmd.Flags().BoolVar(&deepMode, "deep", false, "Add passive endpoint heuristics from page links and common sensitive paths")
	rootCmd.Flags().StringArrayVarP(&customHeaders, "header", "H", nil, "Custom headers (e.g., -H 'Authorization: Bearer token')")
	rootCmd.Flags().StringVar(&discordWebhook, "discord", "", "Discord Webhook URL for alerting on high-priority findings")
	rootCmd.Flags().StringVar(&telegramWebhook, "telegram", "", "Telegram Bot Token and Chat ID (format: token:chat_id)")
	rootCmd.Flags().BoolVar(&update, "update", false, "Alias for the update subcommand")
	_ = update

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, strings.TrimSpace(err.Error()))
		os.Exit(1)
	}
}

func runUpdate() error {
	binDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	installDir := filepath.Join(binDir, ".local", "bin")
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		return err
	}

	assetName := "twreconhunter"
	if runtime.GOOS == "windows" {
		assetName += ".exe"
	}
	if runtime.GOOS == "linux" {
		assetName += "-linux-amd64"
	}
	if runtime.GOOS == "darwin" {
		assetName += "-darwin-arm64"
	}

	url := fmt.Sprintf("https://github.com/tawhid2005/TWReconHunter/releases/latest/download/%s", assetName)
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("update download failed with status %d", resp.StatusCode)
	}

	outPath := filepath.Join(installDir, "twreconhunter")
	if runtime.GOOS == "windows" {
		outPath += ".exe"
	}
	file, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := io.Copy(file, resp.Body); err != nil {
		return err
	}
	if err := file.Chmod(0o755); err != nil {
		return err
	}

	fmt.Printf("Updated binary installed at %s\n", outPath)
	fmt.Println("Run: twreconhunter -u https://example.com --confirm-scope")
	return nil
}
