package main

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPanelCertificate(t *testing.T) {
	certPEM, keyPEM, err := makePanelCertificate(net.ParseIP("203.0.113.42"))
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"203.0.113.42", "127.0.0.1", "localhost"} {
		if err := leaf.VerifyHostname(host); err != nil {
			t.Errorf("certificate rejects %s: %v", host, err)
		}
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("cannot trust generated certificate")
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	server.StartTLS()
	defer server.Close()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "127.0.0.1"}}}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatalf("unexpected HTTPS status %d", response.StatusCode)
	}
}
