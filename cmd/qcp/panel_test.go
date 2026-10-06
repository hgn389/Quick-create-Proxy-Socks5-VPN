package main

import (
	"bytes"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecureUsesSameOriginReferrerPolicy(t *testing.T) {
	p := &panel{}
	handler := p.secure(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	r := httptest.NewRequest(http.MethodGet, "https://127.0.0.1:22689/login", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("unexpected status %d", w.Code)
	}
	if got := w.Header().Get("Referrer-Policy"); got != "same-origin" {
		t.Fatalf("Referrer-Policy = %q, want same-origin", got)
	}
}

func TestSameOrigin(t *testing.T) {
	tests := []struct {
		name         string
		origin       string
		host         string
		tls          bool
		secFetchSite string
		secFetchMode string
		want         bool
	}{
		{name: "missing origin", host: "203.0.113.42:22689", tls: true, want: true},
		{name: "matching HTTPS origin", origin: "https://203.0.113.42:22689", host: "203.0.113.42:22689", tls: true, want: true},
		{name: "case insensitive hostname", origin: "https://PANEL.EXAMPLE:22689", host: "panel.example:22689", tls: true, want: true},
		{name: "different host", origin: "https://evil.example:22689", host: "203.0.113.42:22689", tls: true, want: false},
		{name: "HTTP origin", origin: "http://203.0.113.42:22689", host: "203.0.113.42:22689", tls: true, want: false},
		{name: "matching origin without TLS", origin: "https://203.0.113.42:22689", host: "203.0.113.42:22689", want: false},
		{name: "opaque same-origin navigation", origin: "null", host: "203.0.113.42:22689", tls: true, secFetchSite: "same-origin", secFetchMode: "navigate", want: true},
		{name: "opaque cross-site navigation", origin: "null", host: "203.0.113.42:22689", tls: true, secFetchSite: "cross-site", secFetchMode: "navigate", want: false},
		{name: "opaque same-origin fetch", origin: "null", host: "203.0.113.42:22689", tls: true, secFetchSite: "same-origin", secFetchMode: "cors", want: false},
		{name: "malformed origin", origin: "://bad", host: "203.0.113.42:22689", tls: true, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := http.NewRequest(http.MethodPost, "https://"+tc.host+"/login", nil)
			if err != nil {
				t.Fatal(err)
			}
			r.Host = tc.host
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Sec-Fetch-Site", tc.secFetchSite)
			r.Header.Set("Sec-Fetch-Mode", tc.secFetchMode)
			if tc.tls {
				r.TLS = &tls.ConnectionState{}
			} else {
				r.TLS = nil
			}
			if got := sameOrigin(r); got != tc.want {
				t.Fatalf("sameOrigin() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDashboardShowsQuickProxyActions(t *testing.T) {
	var output bytes.Buffer
	if err := basePage.Execute(&output, pageData{Title: "Tổng quan", CSRF: "test-csrf"}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`action="/proxies/quick/socks5"`,
		`action="/proxies/quick/http"`,
		`value="test-csrf"`,
		`IP:PORT:USER:PASSWORD`,
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("dashboard does not contain %q", want)
		}
	}
}

func TestProxyResultShowsConnectionString(t *testing.T) {
	var output bytes.Buffer
	data := pageData{
		Title:       "Thông tin proxy",
		Proxy:       proxyView{Kind: "socks5", Port: 10000, SourceCIDR: "0.0.0.0/0"},
		ProxyAccess: "203.0.113.10:10000:qcp_user:test-password",
	}
	if err := basePage.Execute(&output, data); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"203.0.113.10:10000:qcp_user:test-password", "TCP 10000", "SOCKS5"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("proxy result does not contain %q", want)
		}
	}
}
