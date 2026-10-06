package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const panelCertPath = etcDir + "/panel.crt"
const panelKeyPath = etcDir + "/panel.key"
const panelHostPath = etcDir + "/panel.host"

func panelCert(ipText string) error {
	if err := mustRoot(); err != nil {
		return err
	}
	ip := net.ParseIP(strings.TrimSpace(ipText)).To4()
	if ip == nil {
		return errors.New("panel-cert requires a valid IPv4 address")
	}
	old, err := os.ReadFile(panelHostPath)
	if err == nil && strings.TrimSpace(string(old)) == ip.String() {
		if _, err := os.Stat(panelCertPath); err == nil {
			if _, err := os.Stat(panelKeyPath); err == nil {
				if pair, err := tls.LoadX509KeyPair(panelCertPath, panelKeyPath); err == nil {
					if leaf, err := x509.ParseCertificate(pair.Certificate[0]); err == nil && leaf.VerifyHostname(ip.String()) == nil && time.Until(leaf.NotAfter) > 30*24*time.Hour {
						return printCertFingerprint()
					}
				}
			}
		}
	}
	group, err := user.LookupGroup("qcp")
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return err
	}
	certPEM, keyPEM, err := makePanelCertificate(ip)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(etcDir, 0711); err != nil {
		return err
	}
	if err := atomicWrite(panelKeyPath, keyPEM, 0640, 0, gid); err != nil {
		return err
	}
	if err := atomicWrite(panelCertPath, certPEM, 0644, 0, 0); err != nil {
		return err
	}
	if err := atomicWrite(panelHostPath, []byte(ip.String()+"\n"), 0644, 0, 0); err != nil {
		return err
	}
	fmt.Println("Panel TLS certificate generated for", ip.String())
	return printCertFingerprint()
}

func makePanelCertificate(ip net.IP) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: ip.String(), Organization: []string{"Quick Create Proxy SOCKS5 VPN"}}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(2, 0, 0), DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), ip}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

func printCertFingerprint() error {
	b, err := os.ReadFile(filepath.Clean(panelCertPath))
	if err != nil {
		return err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return errors.New("invalid panel certificate")
	}
	fingerprint := sha256.Sum256(block.Bytes)
	fmt.Println("Panel certificate SHA256 fingerprint:", hex.EncodeToString(fingerprint[:]))
	fmt.Println("This is a self-signed certificate; compare this fingerprint before accepting the browser warning.")
	return nil
}
