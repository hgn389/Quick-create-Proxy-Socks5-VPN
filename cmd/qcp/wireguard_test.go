package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestWGKeypair(t *testing.T) {
	priv, pub, err := newWGKeypair()
	if err != nil {
		t.Fatal(err)
	}
	a, err := base64.StdEncoding.DecodeString(priv)
	if err != nil || len(a) != 32 {
		t.Fatalf("invalid private key: %v", err)
	}
	b, err := base64.StdEncoding.DecodeString(pub)
	if err != nil || len(b) != 32 {
		t.Fatalf("invalid public key: %v", err)
	}
	if priv == pub {
		t.Fatal("private and public key are equal")
	}
}
func TestEndpointValidation(t *testing.T) {
	for _, v := range []string{"203.0.113.10", "vpn.example.org"} {
		if err := validateEndpoint(v); err != nil {
			t.Errorf("valid %q: %v", v, err)
		}
	}
	for _, v := range []string{"127.0.0.1:123", "evil\nPostUp = x", "2001:db8::1", "bad/domain", "bad..example"} {
		if err := validateEndpoint(v); err == nil {
			t.Errorf("accepted %q", v)
		}
	}
}
func TestWGRenderAndAddress(t *testing.T) {
	p := wireguardPeer{ID: "1234567890abcdef", Name: "iphone", PublicKey: "public", Address: "10.77.93.2", IPv6Address: "fd42:7170:0:93::2", Enabled: true}
	config := string(renderWGServer("server-private", wireguardMeta{Port: 51820}, []wireguardPeer{p}))
	for _, want := range []string{"PrivateKey = server-private", "PublicKey = public", "AllowedIPs = 10.77.93.2/32, fd42:7170:0:93::2/128"} {
		if !strings.Contains(config, want) {
			t.Errorf("missing %q", want)
		}
	}
	v, _, err := nextPeerAddress([]wireguardPeer{p})
	if err != nil || v != "10.77.93.3" {
		t.Fatalf("next address %s: %v", v, err)
	}
	p.Enabled = false
	if strings.Contains(string(renderWGServer("server-private", wireguardMeta{Port: 51820}, []wireguardPeer{p})), "PublicKey = public") {
		t.Fatal("disabled peer included")
	}
}
