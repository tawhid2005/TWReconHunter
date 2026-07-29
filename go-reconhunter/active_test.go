package main

import (
	"net/http"
	"testing"
)

func TestExtractLinks(t *testing.T) {
	body := `<html><body><a href="/login">Login</a><img src="/img/logo.png" /></body></html>`
	links := extractLinks(body, "https://example.com")
	if len(links) != 2 {
		t.Fatalf("expected 2 links, got %d", len(links))
	}
	if links[0] != "https://example.com/login" && links[1] != "https://example.com/login" {
		t.Fatalf("expected login link to be discovered")
	}
}

func TestExtractLinksResolvesRelativeURLs(t *testing.T) {
	body := `<html><body><a href="/admin/users/123">Admin</a></body></html>`
	links := extractLinks(body, "https://example.com/app")
	if len(links) != 1 {
		t.Fatalf("expected 1 link, got %d", len(links))
	}
	if links[0] != "https://example.com/admin/users/123" {
		t.Fatalf("expected relative link to resolve to absolute URL, got %s", links[0])
	}
}

func TestExtractQueryParams(t *testing.T) {
	params := extractQueryParams("https://example.com/?id=1&user=foo")
	if len(params) != 2 {
		t.Fatalf("expected 2 params, got %d", len(params))
	}
	if params[0] != "id" && params[1] != "id" {
		t.Fatalf("expected id parameter")
	}
}

func TestPrioritizeCandidateForParameterizedAdminPath(t *testing.T) {
	priority := prioritizeCandidate("https://example.com/admin/users/123")
	if priority != "P1" {
		t.Fatalf("expected P1 priority for parameterized admin path, got %s", priority)
	}
}

func TestDetectOpenRedirect(t *testing.T) {
	headers := http.Header{}
	headers.Set("Location", "https://evil.example")
	if !detectOpenRedirect(headers, 302) {
		t.Fatal("expected open redirect to be detected")
	}
}
