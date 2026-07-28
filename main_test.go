package main

import (
	"net/http"
	"testing"
)

func TestExtractDomainFromURL(t *testing.T) {
	got := extractDomain("https://app.example.com/path")
	if got != "example.com" {
		t.Fatalf("expected example.com, got %s", got)
	}
}

func TestClassifyEndpointCategory(t *testing.T) {
	cat := classifyEndpointCategory("https://example.com/admin/login")
	if cat != "auth" {
		t.Fatalf("expected auth category, got %s", cat)
	}
}

func TestApplyResearchHeader(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	applyResearchHeader(req, "hacker")
	if got := req.Header.Get("X-HackerOne-Research"); got != "hacker" {
		t.Fatalf("expected research header to be set to hacker, got %q", got)
	}
}

func TestApplyResearchHeaderEmptyValue(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	applyResearchHeader(req, "")
	if got := req.Header.Get("X-HackerOne-Research"); got != "" {
		t.Fatalf("expected empty research header when value is blank, got %q", got)
	}
}
