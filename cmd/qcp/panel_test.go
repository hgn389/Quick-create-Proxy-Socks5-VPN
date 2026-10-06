package main

import (
	"crypto/tls"
	"net/http"
	"testing"
)

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
