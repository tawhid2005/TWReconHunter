package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func runTUI(target string, deepMode bool) error {
	app := tview.NewApplication()

	// Layout elements
	header := tview.NewTextView().
		SetTextAlign(tview.AlignCenter).
		SetText(fmt.Sprintf(" TWReconHunter - Target: %s ", target)).
		SetTextColor(tcell.ColorGreen)

	subdomainList := tview.NewList().ShowSecondaryText(false)
	subdomainList.SetBorder(true).SetTitle(" Subdomains ")

	endpointList := tview.NewList().ShowSecondaryText(true)
	endpointList.SetBorder(true).SetTitle(" Endpoints (Press Enter to Fuzz) ")

	detailsView := tview.NewTextView().
		SetDynamicColors(true).
		SetRegions(true).
		SetWordWrap(true)
	detailsView.SetBorder(true).SetTitle(" Details / Findings ")

	// Grid layout
	grid := tview.NewGrid().
		SetRows(3, 0, 0).
		SetColumns(30, 0).
		SetBorders(true).
		AddItem(header, 0, 0, 1, 2, 0, 0, false).
		AddItem(subdomainList, 1, 0, 2, 1, 0, 0, true).
		AddItem(endpointList, 1, 1, 1, 1, 0, 0, false).
		AddItem(detailsView, 2, 1, 1, 1, 0, 0, false)

	// Update UI functions
	updateDetails := func(text string) {
		app.QueueUpdateDraw(func() {
			detailsView.SetText(text)
		})
	}

	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyTab {
			if app.GetFocus() == subdomainList {
				app.SetFocus(endpointList)
			} else {
				app.SetFocus(subdomainList)
			}
			return nil
		}
		if event.Key() == tcell.KeyCtrlC {
			app.Stop()
			return nil
		}
		return event
	})

	// Initial Scan
	updateDetails("[yellow]Starting passive scan... Please wait.[-]")
	
	go func() {
		result, err := runScanWithOptions(target, "", "", nil, deepMode)
		if err != nil {
			updateDetails(fmt.Sprintf("[red]Error: %v[-]", err))
			return
		}

		app.QueueUpdateDraw(func() {
			for _, sub := range result.Subdomains {
				subdomainList.AddItem(sub, "", 0, nil)
			}
			
			for _, ep := range result.Endpoints {
				categoryColor := "white"
				if ep.Category == "admin" || ep.Category == "auth" {
					categoryColor = "red"
				} else if ep.Category == "api" {
					categoryColor = "yellow"
				}
				
				// Capture url loop variable properly
				epUrl := ep.URL
				
				endpointList.AddItem(
					fmt.Sprintf("[%s]%s[-]", categoryColor, epUrl),
					fmt.Sprintf("Category: %s | Params: %s", ep.Category, strings.Join(ep.Parameters, ", ")),
					0,
					func() {
						// On selection
						updateDetails(fmt.Sprintf("[yellow]Running targeted Fuzzing on: %s...[-]", epUrl))
						go func(selectedURL string) {
							// Simulating a quick fuzzing for TUI
							client := &http.Client{}
							fuzzRes := fuzzHiddenParameters(client, []string{selectedURL})
							dirRes := fuzzSensitiveDirectories(client, selectedURL)
							
							var output string
							if len(fuzzRes) == 0 && len(dirRes) == 0 {
								output = fmt.Sprintf("[green]No hidden params or sensitive files found for %s[-]", selectedURL)
							} else {
								output = fmt.Sprintf("[red]Vulnerabilities Found![+]\n")
								for _, f := range fuzzRes {
									output += fmt.Sprintf("- %s: %s\n", f.Title, f.Detail)
								}
								for _, f := range dirRes {
									output += fmt.Sprintf("- %s: %s\n", f.Title, f.Detail)
								}
							}
							updateDetails(output)
						}(epUrl)
					})
			}
			
			var findingsText string
			if len(result.Findings) > 0 {
				findingsText = "[red]Passive Findings:\n"
				for _, f := range result.Findings {
					findingsText += fmt.Sprintf("- [%s] %s\n", f.Severity, f.Title)
				}
				findingsText += "[-]"
			} else {
				findingsText = "[green]Passive scan completed. No critical secrets found. Select an endpoint above and press Enter to active scan it.[-]"
			}
			updateDetails(findingsText)
		})
	}()

	return app.SetRoot(grid, true).EnableMouse(true).Run()
}
