package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hgn389/quick-create-proxy-socks5-vpn/internal/proxycfg"
	"go.etcd.io/bbolt"
)

const wgUnit = "wg-quick@qcp-wg0.service"
const wgConfigPath = "/etc/wireguard/qcp-wg0.conf"
const wgMetaPath = "/etc/qcp/wireguard.json"
const wgSubnet = "10.77.93.0/24"
const wgIPv6Subnet = "fd42:7170:0:93::/64"

var wgNameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}$`)
var wgHostRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{0,251}[a-zA-Z0-9]$`)

type wireguardMeta struct {
	Endpoint  string `json:"endpoint"`
	Port      int    `json:"port"`
	PublicKey string `json:"public_key"`
	CreatedAt string `json:"created_at"`
}
type wireguardPeer struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	PublicKey       string `json:"public_key"`
	Address         string `json:"address"`
	IPv6Address     string `json:"ipv6_address"`
	Enabled         bool   `json:"enabled"`
	Mode            string `json:"mode"`
	CreatedAt       string `json:"created_at"`
	LatestHandshake string `json:"latest_handshake,omitempty"`
	RXBytes         uint64 `json:"rx_bytes,omitempty"`
	TXBytes         uint64 `json:"tx_bytes,omitempty"`
}
type wireguardView struct {
	Initialized bool            `json:"initialized"`
	Running     bool            `json:"running"`
	Endpoint    string          `json:"endpoint,omitempty"`
	Port        int             `json:"port,omitempty"`
	Peers       []wireguardPeer `json:"peers"`
}
type wireguardInitRequest struct {
	Endpoint string `json:"endpoint"`
	Port     int    `json:"port"`
}
type createPeerRequest struct {
	Name string `json:"name"`
	Mode string `json:"mode"`
}
type createPeerResponse struct {
	Peer         wireguardPeer `json:"peer"`
	ClientConfig string        `json:"client_config"`
}

func newWGKeypair() (string, string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	b[0] &= 248
	b[31] &= 127
	b[31] |= 64
	key, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(key.Bytes()), base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}
func validateEndpoint(s string) error {
	if len(s) < 3 || len(s) > 253 || strings.ContainsAny(s, "/\\: \t\r\n#;[]") {
		return errors.New("endpoint must be an IPv4 address or DNS hostname")
	}
	if ip := net.ParseIP(s); ip != nil {
		if ip.To4() == nil {
			return errors.New("use an IPv4 endpoint in this beta")
		}
		return nil
	}
	if !wgHostRE.MatchString(s) || !strings.Contains(s, ".") || strings.Contains(s, "..") {
		return errors.New("invalid DNS endpoint")
	}
	return nil
}
func loadWGMeta() (wireguardMeta, error) {
	var m wireguardMeta
	b, e := os.ReadFile(wgMetaPath)
	if e != nil {
		return m, e
	}
	e = json.Unmarshal(b, &m)
	return m, e
}
func (a *agent) peers() ([]wireguardPeer, error) {
	peers := []wireguardPeer{}
	err := a.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(peerBucket).ForEach(func(_, v []byte) error {
			var p wireguardPeer
			if e := json.Unmarshal(v, &p); e != nil {
				return e
			}
			peers = append(peers, p)
			return nil
		})
	})
	return peers, err
}
func wgRuntimeStats(peers []wireguardPeer) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "wg", "show", "qcp-wg0", "dump").Output()
	if err != nil {
		return
	}
	byKey := make(map[string]*wireguardPeer)
	for i := range peers {
		byKey[peers[i].PublicKey] = &peers[i]
	}
	for _, line := range strings.Split(string(out), "\n")[1:] {
		f := strings.Split(line, "\t")
		if len(f) < 7 {
			continue
		}
		p := byKey[f[0]]
		if p == nil {
			continue
		}
		t, _ := strconv.ParseInt(f[4], 10, 64)
		if t > 0 {
			p.LatestHandshake = time.Unix(t, 0).UTC().Format(time.RFC3339)
		}
		p.RXBytes, _ = strconv.ParseUint(f[5], 10, 64)
		p.TXBytes, _ = strconv.ParseUint(f[6], 10, 64)
	}
}
func (a *agent) wireguardStatus(w http.ResponseWriter, r *http.Request) {
	peers, err := a.peers()
	if err != nil {
		apiError(w, err, 500)
		return
	}
	m, err := loadWGMeta()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		apiError(w, err, 500)
		return
	}
	v := wireguardView{Initialized: err == nil, Running: serviceActive(wgUnit), Peers: peers}
	if v.Initialized {
		v.Endpoint = m.Endpoint
		v.Port = m.Port
		if v.Running {
			wgRuntimeStats(v.Peers)
		}
	}
	apiJSON(w, v)
}

func (a *agent) enableWireGuard(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	m, err := loadWGMeta()
	if err != nil {
		apiError(w, errors.New("initialize WireGuard first"), 409)
		return
	}
	if serviceActive(wgUnit) {
		apiJSON(w, wireguardView{Initialized: true, Running: true, Endpoint: m.Endpoint, Port: m.Port})
		return
	}
	if err := wireguardAvailable(); err != nil {
		apiError(w, err, 422)
		return
	}
	if err := udpPortAvailable(m.Port); err != nil {
		apiError(w, err, 409)
		return
	}
	if err := systemctl("enable", "--now", wgUnit); err != nil {
		apiError(w, err, 500)
		return
	}
	if err := a.db.Update(func(tx *bbolt.Tx) error { return addAudit(tx, "wireguard.enable", "qcp-wg0") }); err != nil {
		apiError(w, err, 500)
		return
	}
	apiJSON(w, wireguardView{Initialized: true, Running: true, Endpoint: m.Endpoint, Port: m.Port})
}

func (a *agent) disableWireGuard(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	m, err := loadWGMeta()
	if err != nil {
		apiError(w, errors.New("initialize WireGuard first"), 409)
		return
	}
	if err := systemctl("disable", "--now", wgUnit); err != nil {
		apiError(w, err, 500)
		return
	}
	if err := a.db.Update(func(tx *bbolt.Tx) error { return addAudit(tx, "wireguard.disable", "qcp-wg0") }); err != nil {
		apiError(w, err, 500)
		return
	}
	apiJSON(w, wireguardView{Initialized: true, Running: false, Endpoint: m.Endpoint, Port: m.Port})
}
func wireguardAvailable() error {
	for _, cmd := range []string{"wg", "wg-quick", "nft", "ip"} {
		if _, err := exec.LookPath(cmd); err != nil {
			return fmt.Errorf("missing %s; install wireguard-tools, nftables and iproute2", cmd)
		}
	}
	if _, err := os.Stat("/sys/module/wireguard"); err != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if exec.CommandContext(ctx, "modprobe", "-n", "wireguard").Run() != nil {
			return errors.New("running kernel has no detectable WireGuard module")
		}
	}
	return nil
}
func udpPortAvailable(port int) error {
	c, err := net.ListenPacket("udp4", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return fmt.Errorf("UDP port %d is occupied: %w", port, err)
	}
	return c.Close()
}
func renderWGServer(priv string, m wireguardMeta, peers []wireguardPeer) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nAddress = 10.77.93.1/24, fd42:7170:0:93::1/64\nListenPort = %d\nPostUp = /usr/local/bin/qcp wg-route up\nPostDown = /usr/local/bin/qcp wg-route down\n", priv, m.Port)
	for _, p := range peers {
		if !p.Enabled {
			continue
		}
		fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32, %s/128\n", p.PublicKey, p.Address, p.IPv6Address)
	}
	return []byte(b.String())
}
func writeWGServer(priv string, m wireguardMeta, peers []wireguardPeer) error {
	if err := os.MkdirAll("/etc/wireguard", 0700); err != nil {
		return err
	}
	return atomicWrite(wgConfigPath, renderWGServer(priv, m, peers), 0600, 0, 0)
}
func readWGPrivate() (string, error) {
	b, err := os.ReadFile(filepath.Join(etcDir, "secrets", "wg-server.key"))
	return strings.TrimSpace(string(b)), err
}
func (a *agent) initializeWireGuard(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	defer r.Body.Close()
	var input wireguardInitRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if dec.Decode(&input) != nil {
		apiError(w, errors.New("invalid WireGuard request"), 400)
		return
	}
	if err := validateEndpoint(input.Endpoint); err != nil {
		apiError(w, err, 400)
		return
	}
	if input.Port < 1024 || input.Port > 65535 {
		apiError(w, errors.New("UDP port must be 1024–65535"), 400)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := os.Stat(wgMetaPath); err == nil {
		apiError(w, errors.New("WireGuard is already initialized"), 409)
		return
	}
	if err := wireguardAvailable(); err != nil {
		apiError(w, err, 422)
		return
	}
	if err := udpPortAvailable(input.Port); err != nil {
		apiError(w, err, 409)
		return
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		apiError(w, err, 500)
		return
	}
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			_, n, e := net.ParseCIDR(addr.String())
			if e == nil && n.Contains(net.ParseIP("10.77.93.1")) {
				apiError(w, errors.New("WireGuard subnet 10.77.93.0/24 conflicts with an existing interface"), 409)
				return
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	routes, routeErr := exec.CommandContext(ctx, "ip", "-4", "route", "show", "10.77.93.0/24").Output()
	cancel()
	if routeErr != nil {
		apiError(w, fmt.Errorf("cannot inspect IPv4 routes: %w", routeErr), 500)
		return
	}
	if len(bytes.TrimSpace(routes)) != 0 {
		apiError(w, errors.New("WireGuard subnet 10.77.93.0/24 conflicts with an existing route"), 409)
		return
	}
	priv, pub, err := newWGKeypair()
	if err != nil {
		apiError(w, err, 500)
		return
	}
	m := wireguardMeta{Endpoint: input.Endpoint, Port: input.Port, PublicKey: pub, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	if err := os.MkdirAll(filepath.Join(etcDir, "secrets"), 0700); err != nil {
		apiError(w, err, 500)
		return
	}
	keyPath := filepath.Join(etcDir, "secrets", "wg-server.key")
	if err := atomicWrite(keyPath, []byte(priv+"\n"), 0600, 0, 0); err != nil {
		apiError(w, err, 500)
		return
	}
	cleanup := func() {
		_ = systemctl("disable", "--now", wgUnit)
		_ = os.Remove(wgConfigPath)
		_ = os.Remove(keyPath)
		_ = os.Remove(wgMetaPath)
	}
	if err := writeWGServer(priv, m, nil); err != nil {
		cleanup()
		apiError(w, err, 500)
		return
	}
	metaJSON, _ := json.Marshal(m)
	if err := atomicWrite(wgMetaPath, metaJSON, 0600, 0, 0); err != nil {
		cleanup()
		apiError(w, err, 500)
		return
	}
	if err := systemctl("enable", "--now", wgUnit); err != nil {
		cleanup()
		apiError(w, fmt.Errorf("WireGuard service failed: %w", err), 500)
		return
	}
	if err := a.db.Update(func(tx *bbolt.Tx) error { return addAudit(tx, "wireguard.initialize", "qcp-wg0") }); err != nil {
		cleanup()
		apiError(w, err, 500)
		return
	}
	apiJSON(w, wireguardView{Initialized: true, Running: true, Endpoint: m.Endpoint, Port: m.Port, Peers: []wireguardPeer{}})
}
func nextPeerAddress(peers []wireguardPeer) (string, string, error) {
	used := map[string]bool{}
	for _, p := range peers {
		used[p.Address] = true
	}
	for i := 2; i < 255; i++ {
		v := fmt.Sprintf("10.77.93.%d", i)
		if !used[v] {
			return v, fmt.Sprintf("fd42:7170:0:93::%x", i), nil
		}
	}
	return "", "", errors.New("WireGuard subnet is full")
}
func (a *agent) savePeer(p wireguardPeer, action string) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return a.db.Update(func(tx *bbolt.Tx) error {
		if err := tx.Bucket(peerBucket).Put([]byte(p.ID), b); err != nil {
			return err
		}
		return addAudit(tx, action, p.ID)
	})
}
func (a *agent) getPeer(id string) (wireguardPeer, error) {
	var p wireguardPeer
	if !validID.MatchString(id) {
		return p, errors.New("invalid peer ID")
	}
	err := a.db.View(func(tx *bbolt.Tx) error {
		v := tx.Bucket(peerBucket).Get([]byte(id))
		if v == nil {
			return os.ErrNotExist
		}
		return json.Unmarshal(v, &p)
	})
	return p, err
}
func (a *agent) applyPeers(peers []wireguardPeer) error {
	m, err := loadWGMeta()
	if err != nil {
		return err
	}
	priv, err := readWGPrivate()
	if err != nil {
		return err
	}
	old, err := os.ReadFile(wgConfigPath)
	if err != nil {
		return err
	}
	if err := writeWGServer(priv, m, peers); err != nil {
		return err
	}
	// A service restart applies a complete peer set. Restore the old configuration on failure.
	if err := systemctl("restart", wgUnit); err != nil {
		_ = atomicWrite(wgConfigPath, old, 0600, 0, 0)
		_ = systemctl("restart", wgUnit)
		return err
	}
	return nil
}
func (a *agent) createWireGuardPeer(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	defer r.Body.Close()
	var input createPeerRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if dec.Decode(&input) != nil || !wgNameRE.MatchString(input.Name) {
		apiError(w, errors.New("name must be 1–32 letters, numbers, _ or -"), 400)
		return
	}
	if input.Mode != "full" && input.Mode != "split" {
		apiError(w, errors.New("WireGuard mode must be full or split"), 400)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	m, err := loadWGMeta()
	if err != nil {
		apiError(w, errors.New("initialize WireGuard first"), 409)
		return
	}
	if !serviceActive(wgUnit) {
		apiError(w, errors.New("WireGuard service is stopped"), 409)
		return
	}
	peers, err := a.peers()
	if err != nil {
		apiError(w, err, 500)
		return
	}
	if len(peers) >= 253 {
		apiError(w, errors.New("peer limit reached"), 409)
		return
	}
	for _, p := range peers {
		if p.Name == input.Name {
			apiError(w, errors.New("peer name already exists"), 409)
			return
		}
	}
	ipv4, ipv6, err := nextPeerAddress(peers)
	if err != nil {
		apiError(w, err, 409)
		return
	}
	priv, pub, err := newWGKeypair()
	if err != nil {
		apiError(w, err, 500)
		return
	}
	id, err := proxycfg.NewID()
	if err != nil {
		apiError(w, err, 500)
		return
	}
	p := wireguardPeer{ID: id, Name: input.Name, PublicKey: pub, Address: ipv4, IPv6Address: ipv6, Enabled: true, Mode: input.Mode, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	if err := a.applyPeers(append(peers, p)); err != nil {
		apiError(w, err, 500)
		return
	}
	if err := a.savePeer(p, "wireguard.peer.create"); err != nil {
		_ = a.applyPeers(peers)
		apiError(w, err, 500)
		return
	}
	allowed := "0.0.0.0/0, ::/0"
	dns := "DNS = 1.1.1.1\n"
	if input.Mode == "split" {
		allowed = "10.77.93.0/24, fd42:7170:0:93::/64"
		dns = ""
	}
	config := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s/32, %s/128\n%s\n[Peer]\nPublicKey = %s\nEndpoint = %s:%d\nAllowedIPs = %s\nPersistentKeepalive = 25\n", priv, ipv4, ipv6, dns, m.PublicKey, m.Endpoint, m.Port, allowed)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(createPeerResponse{Peer: p, ClientConfig: config})
}
func (a *agent) togglePeer(w http.ResponseWriter, r *http.Request, enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p, err := a.getPeer(r.PathValue("id"))
	if err != nil {
		apiError(w, err, 404)
		return
	}
	if p.Enabled == enabled {
		apiJSON(w, p)
		return
	}
	peers, err := a.peers()
	if err != nil {
		apiError(w, err, 500)
		return
	}
	old := p
	p.Enabled = enabled
	for i := range peers {
		if peers[i].ID == p.ID {
			peers[i] = p
			break
		}
	}
	if err := a.applyPeers(peers); err != nil {
		apiError(w, err, 500)
		return
	}
	action := "wireguard.peer.disable"
	if enabled {
		action = "wireguard.peer.enable"
	}
	if err := a.savePeer(p, action); err != nil {
		for i := range peers {
			if peers[i].ID == p.ID {
				peers[i] = old
				break
			}
		}
		_ = a.applyPeers(peers)
		apiError(w, err, 500)
		return
	}
	apiJSON(w, p)
}
func (a *agent) enableWireGuardPeer(w http.ResponseWriter, r *http.Request) { a.togglePeer(w, r, true) }
func (a *agent) disableWireGuardPeer(w http.ResponseWriter, r *http.Request) {
	a.togglePeer(w, r, false)
}
func (a *agent) deleteWireGuardPeer(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p, err := a.getPeer(r.PathValue("id"))
	if err != nil {
		apiError(w, err, 404)
		return
	}
	peers, err := a.peers()
	if err != nil {
		apiError(w, err, 500)
		return
	}
	remaining := make([]wireguardPeer, 0, len(peers)-1)
	for _, item := range peers {
		if item.ID != p.ID {
			remaining = append(remaining, item)
		}
	}
	if err := a.applyPeers(remaining); err != nil {
		apiError(w, err, 500)
		return
	}
	if err := a.db.Update(func(tx *bbolt.Tx) error {
		if err := tx.Bucket(peerBucket).Delete([]byte(p.ID)); err != nil {
			return err
		}
		return addAudit(tx, "wireguard.peer.delete", p.ID)
	}); err != nil {
		_ = a.applyPeers(peers)
		apiError(w, err, 500)
		return
	}
	w.WriteHeader(204)
}

func wireguardRoute(action string) error {
	if err := mustRoot(); err != nil {
		return err
	}
	if action == "down" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = exec.CommandContext(ctx, "nft", "delete", "table", "ip", "qcp_wg_nat").Run()
		old, err := os.ReadFile(filepath.Join(stateDir, "ip_forward.original"))
		if err == nil && strings.TrimSpace(string(old)) == "0" {
			_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("0\n"), 0644)
		}
		_ = os.Remove(filepath.Join(stateDir, "ip_forward.original"))
		return nil
	}
	if action != "up" {
		return errors.New("invalid wg-route action")
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return err
	}
	old, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(stateDir, "ip_forward.original")); errors.Is(err, os.ErrNotExist) {
		if err := atomicWrite(filepath.Join(stateDir, "ip_forward.original"), old, 0600, 0, 0); err != nil {
			return err
		}
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644); err != nil {
		return err
	}
	// This project owns only its NAT table. Existing firewall chains and webserver rules are untouched.
	script := []byte("table ip qcp_wg_nat {\n chain postrouting {\n  type nat hook postrouting priority srcnat; policy accept;\n  ip saddr 10.77.93.0/24 oifname != \"qcp-wg0\" masquerade\n }\n}\n")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = bytes.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if strings.TrimSpace(string(old)) == "0" {
			_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("0\n"), 0644)
		}
		_ = os.Remove(filepath.Join(stateDir, "ip_forward.original"))
		return fmt.Errorf("nft NAT setup: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}
