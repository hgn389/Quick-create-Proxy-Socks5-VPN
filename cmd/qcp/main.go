package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hgn389/quick-create-proxy-socks5-vpn/internal/proxycfg"
	"go.etcd.io/bbolt"
	"golang.org/x/crypto/bcrypt"
)

const (
	version              = "1.0.0-beta.3"
	etcDir               = "/etc/qcp"
	stateDir             = "/var/lib/qcp"
	runDir               = "/run/qcp"
	panelAddr            = "0.0.0.0:22689"
	proxyUnitName        = "qcp-proxy@%s.service"
	defaultAdminPassword = "12345687"
	adminMustChangePath  = etcDir + "/admin.must-change"
)

var validID = regexp.MustCompile(`^[a-f0-9]{16}$`)
var proxyBucket = []byte("proxies")
var auditBucket = []byte("audit")
var peerBucket = []byte("wireguard_peers")

type agent struct {
	db *bbolt.DB
	mu sync.Mutex
}

type createProxyRequest struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Port       int    `json:"port"`
	Username   string `json:"username"`
	SourceCIDR string `json:"source_cidr"`
}

type proxyView struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Port       int    `json:"port"`
	Username   string `json:"username"`
	SourceCIDR string `json:"source_cidr"`
	Enabled    bool   `json:"enabled"`
	CreatedAt  string `json:"created_at"`
	Running    bool   `json:"running"`
}

type createProxyResponse struct {
	Proxy    proxyView `json:"proxy"`
	Password string    `json:"password"`
}

type changeAdminPasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "version":
		fmt.Println(version)
	case "agent":
		err = runAgent()
	case "panel":
		err = runPanel()
	case "admin":
		if len(os.Args) != 3 || (os.Args[2] != "bootstrap" && os.Args[2] != "rotate") {
			err = errors.New("usage: qcp admin bootstrap|rotate")
		} else {
			err = setAdminPassword(os.Args[2] == "rotate")
		}
	case "doctor":
		err = doctor()
	case "wg-route":
		if len(os.Args) != 3 || (os.Args[2] != "up" && os.Args[2] != "down") {
			err = errors.New("usage: qcp wg-route up|down")
		} else {
			err = wireguardRoute(os.Args[2])
		}
	case "panel-cert":
		if len(os.Args) != 3 {
			err = errors.New("usage: qcp panel-cert IPv4_ADDRESS")
		} else {
			err = panelCert(os.Args[2])
		}
	case "update":
		if len(os.Args) != 4 || os.Args[2] != "apply" {
			err = errors.New("usage: qcp update apply TAG")
		} else {
			err = updateCLI(os.Args[3])
		}
	case "firewall":
		if len(os.Args) != 3 || (os.Args[2] != "up" && os.Args[2] != "down") {
			err = errors.New("usage: qcp firewall up|down")
		} else {
			err = panelFirewall(os.Args[2])
		}
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		log.Printf("ERROR: %v", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage: qcp version|doctor|agent|panel|admin bootstrap|admin rotate|panel-cert IPv4_ADDRESS|update apply TAG|firewall up|down|wg-route up|down")
}

func mustRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("this command requires root")
	}
	return nil
}

func setAdminPassword(rotate bool) error {
	if err := mustRoot(); err != nil {
		return err
	}
	path := filepath.Join(etcDir, "admin.hash")
	if !rotate {
		if _, err := os.Stat(path); err == nil {
			return errors.New("admin password already initialized; use admin rotate")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	secret := defaultAdminPassword
	if rotate {
		var err error
		secret, err = proxycfg.NewPassword()
		if err != nil {
			return err
		}
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), 12)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(etcDir, 0750); err != nil {
		return err
	}
	grp, err := user.LookupGroup("qcp")
	if err != nil {
		return fmt.Errorf("qcp group must exist before admin setup: %w", err)
	}
	gid, err := strconv.Atoi(grp.Gid)
	if err != nil {
		return err
	}
	if err := atomicWrite(path, hash, 0640, 0, gid); err != nil {
		return err
	}
	if !rotate {
		if err := atomicWrite(adminMustChangePath, []byte("change required\n"), 0640, 0, gid); err != nil {
			return err
		}
	} else {
		_ = os.Remove(adminMustChangePath)
	}
	fmt.Fprintln(os.Stdout, "Admin account: admin")
	fmt.Fprintln(os.Stdout, "Admin password:", secret)
	if !rotate {
		fmt.Fprintln(os.Stdout, "You must change this default password after the first login.")
	}
	fmt.Fprintln(os.Stdout, "This password is not written to application logs.")
	return nil
}

func doctor() error {
	fmt.Println("qcp", version)
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return errors.New("systemd is not running")
	}
	if _, err := os.Stat("/usr/local/libexec/qcp/3proxy"); err == nil {
		fmt.Println("3proxy: /usr/local/libexec/qcp/3proxy")
	} else {
		fmt.Println("3proxy: unavailable")
	}
	for _, executable := range []string{"wg", "wg-quick", "nft", "systemctl"} {
		path, err := exec.LookPath(executable)
		if err == nil {
			fmt.Printf("%s: %s\n", executable, path)
		} else {
			fmt.Printf("%s: unavailable\n", executable)
		}
	}
	if _, err := os.Stat(filepath.Join(runDir, "agent.sock")); err == nil {
		fmt.Println("agent socket: present")
	} else {
		fmt.Println("agent socket: unavailable")
	}
	return nil
}

func runAgent() error {
	if err := mustRoot(); err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(etcDir, "proxies"), 0750); err != nil {
		return err
	}
	db, err := bbolt.Open(filepath.Join(stateDir, "state.db"), 0600, &bbolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.Update(func(tx *bbolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(proxyBucket); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(auditBucket)
		if err != nil {
			return err
		}
		_, err = tx.CreateBucketIfNotExists(peerBucket)
		return err
	}); err != nil {
		return err
	}
	group, err := user.LookupGroup("qcp")
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(runDir, 0750); err != nil {
		return err
	}
	if err := os.Chown(runDir, 0, gid); err != nil {
		return err
	}
	if err := os.Chmod(runDir, 0750); err != nil {
		return err
	}
	socket := filepath.Join(runDir, "agent.sock")
	if err := os.Remove(socket); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(socket)
	if err := os.Chown(socket, 0, gid); err != nil {
		return err
	}
	if err := os.Chmod(socket, 0660); err != nil {
		return err
	}
	a := &agent{db: db}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", a.status)
	mux.HandleFunc("GET /v1/proxies", a.listProxies)
	mux.HandleFunc("POST /v1/proxies", a.createProxy)
	mux.HandleFunc("POST /v1/proxies/{id}/enable", a.enableProxy)
	mux.HandleFunc("POST /v1/proxies/{id}/disable", a.disableProxy)
	mux.HandleFunc("POST /v1/proxies/{id}/restart", a.restartProxy)
	mux.HandleFunc("DELETE /v1/proxies/{id}", a.deleteProxy)
	mux.HandleFunc("POST /v1/admin/password", a.changeAdminPassword)
	mux.HandleFunc("GET /v1/wireguard", a.wireguardStatus)
	mux.HandleFunc("GET /v1/update", a.checkUpdate)
	mux.HandleFunc("POST /v1/update", a.startUpdate)
	mux.HandleFunc("POST /v1/wireguard", a.initializeWireGuard)
	mux.HandleFunc("POST /v1/wireguard/enable", a.enableWireGuard)
	mux.HandleFunc("POST /v1/wireguard/disable", a.disableWireGuard)
	mux.HandleFunc("POST /v1/wireguard/peers", a.createWireGuardPeer)
	mux.HandleFunc("POST /v1/wireguard/peers/{id}/enable", a.enableWireGuardPeer)
	mux.HandleFunc("POST /v1/wireguard/peers/{id}/disable", a.disableWireGuardPeer)
	mux.HandleFunc("DELETE /v1/wireguard/peers/{id}", a.deleteWireGuardPeer)
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 16 << 10}
	log.Printf("qcp agent ready on local Unix socket")
	return server.Serve(listener)
}

func (a *agent) changeAdminPassword(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var input changeAdminPasswordRequest
	if err := dec.Decode(&input); err != nil {
		apiError(w, errors.New("invalid password request"), http.StatusBadRequest)
		return
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		apiError(w, errors.New("request contains extra data"), http.StatusBadRequest)
		return
	}
	if err := validateNewAdminPassword(input.NewPassword); err != nil {
		apiError(w, err, http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	path := filepath.Join(etcDir, "admin.hash")
	currentHash, err := os.ReadFile(path)
	if err != nil {
		apiError(w, err, http.StatusInternalServerError)
		return
	}
	if bcrypt.CompareHashAndPassword(currentHash, []byte(input.CurrentPassword)) != nil {
		apiError(w, errors.New("current password is incorrect"), http.StatusUnauthorized)
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(input.NewPassword), 12)
	if err != nil {
		apiError(w, err, http.StatusInternalServerError)
		return
	}
	grp, err := user.LookupGroup("qcp")
	if err != nil {
		apiError(w, err, http.StatusInternalServerError)
		return
	}
	gid, err := strconv.Atoi(grp.Gid)
	if err != nil {
		apiError(w, err, http.StatusInternalServerError)
		return
	}
	if err := atomicWrite(path, newHash, 0640, 0, gid); err != nil {
		apiError(w, err, http.StatusInternalServerError)
		return
	}
	if err := os.Remove(adminMustChangePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		apiError(w, err, http.StatusInternalServerError)
		return
	}
	if err := a.db.Update(func(tx *bbolt.Tx) error { return addAudit(tx, "admin.password.change", "admin") }); err != nil {
		log.Printf("write password-change audit event: %v", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

func validateNewAdminPassword(password string) error {
	if len(password) < 8 || len(password) > 72 {
		return errors.New("new password must contain 8–72 bytes")
	}
	if password == defaultAdminPassword {
		return errors.New("choose a password different from the default password")
	}
	return nil
}

func (a *agent) status(w http.ResponseWriter, r *http.Request) {
	list, err := a.proxies()
	if err != nil {
		apiError(w, err, http.StatusInternalServerError)
		return
	}
	running := 0
	for _, p := range list {
		if p.Running {
			running++
		}
	}
	apiJSON(w, map[string]any{"version": version, "proxy_count": len(list), "running_proxies": running, "proxies": list})
}

func (a *agent) listProxies(w http.ResponseWriter, r *http.Request) {
	list, err := a.proxies()
	if err != nil {
		apiError(w, err, http.StatusInternalServerError)
		return
	}
	apiJSON(w, list)
}

func (a *agent) proxies() ([]proxyView, error) {
	var list []proxyView
	err := a.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(proxyBucket).ForEach(func(_, value []byte) error {
			var p proxycfg.Spec
			if err := json.Unmarshal(value, &p); err != nil {
				return err
			}
			list = append(list, viewProxy(p))
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	for i := range list {
		list[i].Running = serviceActive(fmt.Sprintf(proxyUnitName, list[i].ID))
	}
	return list, nil
}

func viewProxy(p proxycfg.Spec) proxyView {
	return proxyView{ID: p.ID, Name: p.Name, Kind: p.Kind, Port: p.Port, Username: p.Username, SourceCIDR: p.SourceCIDR, Enabled: p.Enabled, CreatedAt: p.CreatedAt}
}

func (a *agent) createProxy(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var input createProxyRequest
	if err := dec.Decode(&input); err != nil {
		apiError(w, errors.New("invalid proxy request"), http.StatusBadRequest)
		return
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		apiError(w, errors.New("request contains extra data"), http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	password, err := proxycfg.NewPassword()
	if err != nil {
		apiError(w, err, http.StatusInternalServerError)
		return
	}
	id, err := proxycfg.NewID()
	if err != nil {
		apiError(w, err, http.StatusInternalServerError)
		return
	}
	hash, err := proxycfg.HashPassword(password)
	if err != nil {
		apiError(w, err, http.StatusInternalServerError)
		return
	}
	p := proxycfg.Spec{ID: id, Name: input.Name, Kind: input.Kind, Port: input.Port, Username: input.Username, SourceCIDR: input.SourceCIDR, PasswordCR: hash, Enabled: true, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	config, err := proxycfg.Render(p)
	if err != nil {
		apiError(w, err, http.StatusBadRequest)
		return
	}
	if err := a.assertPortUnused(p.Port); err != nil {
		apiError(w, err, http.StatusConflict)
		return
	}
	if err := portAvailable(p.Port); err != nil {
		apiError(w, err, http.StatusConflict)
		return
	}
	group, err := user.LookupGroup("qcp-proxy")
	if err != nil {
		apiError(w, err, http.StatusInternalServerError)
		return
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		apiError(w, err, http.StatusInternalServerError)
		return
	}
	path := proxyConfigPath(p.ID)
	if err := atomicWrite(path, []byte(config), 0640, 0, gid); err != nil {
		apiError(w, err, http.StatusInternalServerError)
		return
	}
	unit := fmt.Sprintf(proxyUnitName, p.ID)
	if err := systemctl("enable", "--now", unit); err != nil {
		_ = systemctl("disable", "--now", unit)
		_ = os.Remove(path)
		apiError(w, fmt.Errorf("proxy service could not start: %w", err), http.StatusInternalServerError)
		return
	}
	if err := waitPort(p.Port); err != nil {
		_ = systemctl("disable", "--now", unit)
		_ = os.Remove(path)
		apiError(w, fmt.Errorf("proxy listener failed health check: %w", err), http.StatusInternalServerError)
		return
	}
	data, err := json.Marshal(p)
	if err == nil {
		err = a.db.Update(func(tx *bbolt.Tx) error {
			if err := tx.Bucket(proxyBucket).Put([]byte(p.ID), data); err != nil {
				return err
			}
			return addAudit(tx, "proxy.create", p.ID)
		})
	}
	if err != nil {
		_ = systemctl("disable", "--now", unit)
		_ = os.Remove(path)
		apiError(w, err, http.StatusInternalServerError)
		return
	}
	v := viewProxy(p)
	v.Running = true
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(createProxyResponse{Proxy: v, Password: password})
}

func (a *agent) assertPortUnused(port int) error {
	return a.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(proxyBucket).ForEach(func(_, value []byte) error {
			var p proxycfg.Spec
			if err := json.Unmarshal(value, &p); err != nil {
				return err
			}
			if p.Port == port {
				return errors.New("port is already assigned to another proxy")
			}
			return nil
		})
	})
}

func (a *agent) getProxy(id string) (proxycfg.Spec, error) {
	if !validID.MatchString(id) {
		return proxycfg.Spec{}, errors.New("invalid proxy ID")
	}
	var p proxycfg.Spec
	err := a.db.View(func(tx *bbolt.Tx) error {
		v := tx.Bucket(proxyBucket).Get([]byte(id))
		if v == nil {
			return os.ErrNotExist
		}
		return json.Unmarshal(v, &p)
	})
	return p, err
}

func (a *agent) updateProxy(p proxycfg.Spec, action string) error {
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return a.db.Update(func(tx *bbolt.Tx) error {
		if err := tx.Bucket(proxyBucket).Put([]byte(p.ID), data); err != nil {
			return err
		}
		return addAudit(tx, action, p.ID)
	})
}

func (a *agent) enableProxy(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p, err := a.getProxy(r.PathValue("id"))
	if err != nil {
		apiError(w, err, http.StatusNotFound)
		return
	}
	if p.Enabled {
		apiJSON(w, viewProxy(p))
		return
	}
	if err := portAvailable(p.Port); err != nil {
		apiError(w, err, http.StatusConflict)
		return
	}
	unit := fmt.Sprintf(proxyUnitName, p.ID)
	if err := systemctl("enable", "--now", unit); err != nil {
		apiError(w, err, http.StatusInternalServerError)
		return
	}
	if err := waitPort(p.Port); err != nil {
		_ = systemctl("disable", "--now", unit)
		apiError(w, err, http.StatusInternalServerError)
		return
	}
	p.Enabled = true
	if err := a.updateProxy(p, "proxy.enable"); err != nil {
		_ = systemctl("disable", "--now", unit)
		apiError(w, err, http.StatusInternalServerError)
		return
	}
	apiJSON(w, viewProxy(p))
}

func (a *agent) disableProxy(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p, err := a.getProxy(r.PathValue("id"))
	if err != nil {
		apiError(w, err, http.StatusNotFound)
		return
	}
	unit := fmt.Sprintf(proxyUnitName, p.ID)
	if err := systemctl("disable", "--now", unit); err != nil {
		apiError(w, err, http.StatusInternalServerError)
		return
	}
	p.Enabled = false
	if err := a.updateProxy(p, "proxy.disable"); err != nil {
		apiError(w, err, http.StatusInternalServerError)
		return
	}
	apiJSON(w, viewProxy(p))
}

func (a *agent) restartProxy(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p, err := a.getProxy(r.PathValue("id"))
	if err != nil {
		apiError(w, err, http.StatusNotFound)
		return
	}
	if !p.Enabled {
		apiError(w, errors.New("proxy is disabled"), http.StatusConflict)
		return
	}
	if err := systemctl("restart", fmt.Sprintf(proxyUnitName, p.ID)); err != nil {
		apiError(w, err, http.StatusInternalServerError)
		return
	}
	if err := waitPort(p.Port); err != nil {
		apiError(w, err, http.StatusInternalServerError)
		return
	}
	if err := a.db.Update(func(tx *bbolt.Tx) error { return addAudit(tx, "proxy.restart", p.ID) }); err != nil {
		apiError(w, err, http.StatusInternalServerError)
		return
	}
	v := viewProxy(p)
	v.Running = true
	apiJSON(w, v)
}

func (a *agent) deleteProxy(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p, err := a.getProxy(r.PathValue("id"))
	if err != nil {
		apiError(w, err, http.StatusNotFound)
		return
	}
	unit := fmt.Sprintf(proxyUnitName, p.ID)
	if err := systemctl("disable", "--now", unit); err != nil {
		apiError(w, err, http.StatusInternalServerError)
		return
	}
	if err := os.Remove(proxyConfigPath(p.ID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		apiError(w, err, http.StatusInternalServerError)
		return
	}
	if err := a.db.Update(func(tx *bbolt.Tx) error {
		if err := tx.Bucket(proxyBucket).Delete([]byte(p.ID)); err != nil {
			return err
		}
		return addAudit(tx, "proxy.delete", p.ID)
	}); err != nil {
		apiError(w, err, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func proxyConfigPath(id string) string {
	return filepath.Join(etcDir, "proxies", id+".cfg")
}

func addAudit(tx *bbolt.Tx, action, id string) error {
	b := tx.Bucket(auditBucket)
	seq, err := b.NextSequence()
	if err != nil {
		return err
	}
	entry, err := json.Marshal(map[string]any{"time": time.Now().UTC().Format(time.RFC3339Nano), "action": action, "object_id": id})
	if err != nil {
		return err
	}
	return b.Put([]byte(fmt.Sprintf("%020d", seq)), entry)
}

func systemctl(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %s: %w", strings.Join(args, " "), strings.TrimSpace(string(out)), err)
	}
	return nil
}

func serviceActive(unit string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", unit).Run() == nil
}

func portAvailable(port int) error {
	l, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return fmt.Errorf("TCP port %d is occupied: %w", port, err)
	}
	return l.Close()
}

func waitPort(port int) error {
	address := fmt.Sprintf("127.0.0.1:%d", port)
	for i := 0; i < 20; i++ {
		conn, err := net.DialTimeout("tcp4", address, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	return fmt.Errorf("port %d did not open", port)
}

func atomicWrite(path string, content []byte, mode os.FileMode, uid, gid int) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".qcp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chown(uid, gid); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(content); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func apiError(w http.ResponseWriter, err error, status int) {
	// The API is accessible only through the local Unix socket. Avoid echoing
	// request bodies or configuration content in errors.
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func apiJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(value)
}

func agentClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(runDir, "agent.sock"))
		},
	}}
}

func agentRequest(method, path string, input, output any) error {
	var body io.Reader
	if input != nil {
		b, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, "http://unix"+path, body)
	if err != nil {
		return err
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := agentClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		var result struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&result)
		if result.Error == "" {
			result.Error = resp.Status
		}
		return errors.New(result.Error)
	}
	if output != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(output)
	}
	return nil
}
