package main

import "testing"

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
