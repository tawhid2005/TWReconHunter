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

	rootCmd := &cobra.Command{
		Use:   "twreconhunter",
		Short: "Passive recon and manual review assistant",
		Long: `TWReconHunter is a passive reconnaissance tool for authorized security testing.

Examples:
  twreconhunter -u https://example.com --confirm-scope
  twreconhunter --url https://example.com --confirm-scope --scope-domain example.com
  twreconhunter update

This tool performs passive checks only. It does not send exploit payloads.
`,
		Example: `  twreconhunter -u https://example.com --confirm-scope
  twreconhunter update`,
	}

	rootCmd.RunE = func(cmd *cobra.Command, args []string) error {
		if target == "" {
			return fmt.Errorf("target URL is required")
		}

		if !confirmScope {
			fmt.Println("Authorization warning: confirm that this target is in scope before proceeding.")
			return nil
		}

		fmt.Printf("Target: %s\n", target)
		if scopeDomain != "" {
			fmt.Printf("Scope domain: %s\n", scopeDomain)
		}

		result, err := runScan(target, scopeDomain)
		if err != nil {
			return err
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
		fmt.Println("\nPassive scan completed.")
		return nil
	}

	var update bool
	rootCmd.AddCommand(&cobra.Command{
		Use:     "update",
		Short:   "Download the latest binary from GitHub",
		Long:    "Download and install the latest release binary for this platform.",
		Example: `  twreconhunter update`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUpdate()
		},
	})

	rootCmd.Flags().StringVarP(&target, "url", "u", "", "Target URL or domain")
	rootCmd.Flags().BoolVar(&confirmScope, "confirm-scope", false, "Confirm that the target is authorized for testing")
	rootCmd.Flags().StringVar(&scopeDomain, "scope-domain", "", "Optional in-scope domain")
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
