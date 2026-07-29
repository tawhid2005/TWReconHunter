package main

import (
	"net/http"
	"testing"
)

func TestExtractLinks(t *testing.T) {
	body := `<html><body><a href="/login">Login</a><img src="/img/logo.png" /></body></html>`
	links := extractLinks(body)
	if len(links) != 2 {
		t.Fatalf("expected 2 links, got %d", len(links))
	}
	if links[0] != "/login" && links[1] != "/login" {
		t.Fatalf("expected login link to be discovered")
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

func TestDetectOpenRedirect(t *testing.T) {
	headers := http.Header{}
	headers.Set("Location", "https://evil.example")
	if !detectOpenRedirect(headers, 302) {
		t.Fatal("expected open redirect to be detected")
	}
}
