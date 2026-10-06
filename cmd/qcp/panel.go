package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
)

type session struct {
	CSRF      string
	HashEpoch [32]byte
	Created   time.Time
	LastSeen  time.Time
}

type loginBucket struct {
	Failures int
	Started  time.Time
	Blocked  time.Time
}

type panel struct {
	mu       sync.Mutex
	sessions map[string]session
	logins   map[string]loginBucket
}

type pageData struct {
	Title      string
	AppVersion string
	CSRF       string
	Error      string
	Notice     string
	Status     struct {
		Version        string      `json:"version"`
		ProxyCount     int         `json:"proxy_count"`
		RunningProxies int         `json:"running_proxies"`
		Proxies        []proxyView `json:"proxies"`
	}
	Proxy        proxyView
	Password     string
	WireGuard    wireguardView
	Peer         wireguardPeer
	ClientConfig string
	QRCode       template.URL
	Update       updateView
}

var basePage = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}} · QCP</title><style>
:root{font-family:system-ui,-apple-system,Segoe UI,sans-serif;color:#10213d;background:#f3f6fb}
*{box-sizing:border-box}body{margin:0}header{background:#0d1c39;color:white;padding:1rem 1.5rem;display:flex;justify-content:space-between;align-items:center;gap:1rem}
header strong{font-size:1.1rem}header form{margin:0}main{max-width:1100px;margin:2rem auto;padding:0 1rem}.card{background:white;border:1px solid #dce4ef;border-radius:12px;padding:1.25rem;margin-bottom:1rem;box-shadow:0 2px 8px #132b5010}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:1rem}.metric{font-size:1.8rem;font-weight:700;margin:.3rem 0}.muted{color:#64748b}
label{display:block;font-weight:600;margin:.8rem 0 .25rem}input,select{width:100%;max-width:480px;padding:.7rem;border:1px solid #b8c6d8;border-radius:7px;font:inherit}
button,.button{display:inline-block;border:0;border-radius:7px;background:#1d5fe5;color:white;padding:.7rem 1rem;font:inherit;cursor:pointer;text-decoration:none}
button.secondary,.button.secondary{background:#e9eef6;color:#163457}button.danger{background:#ba2632}button:disabled{opacity:.5;cursor:not-allowed}
.row{display:flex;gap:.5rem;align-items:center;flex-wrap:wrap}.row form{display:inline;margin:0}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:.7rem;border-bottom:1px solid #e7edf5}td:last-child{white-space:nowrap}
.scroll{overflow-x:auto}.error{background:#fff0f0;color:#9d1e28;padding:.7rem;border-radius:7px}.notice{background:#e7f6ed;color:#126038;padding:.7rem;border-radius:7px}
.secret{font-family:ui-monospace,SFMono-Regular,monospace;overflow-wrap:anywhere;background:#eff4fc;padding:1rem;border-radius:8px;font-size:1.05rem;white-space:pre-wrap}.qr{max-width:280px;width:100%;image-rendering:pixelated}
small{color:#64748b;display:block;margin:.25rem 0 .7rem}h1{margin-top:0}footer{max-width:1100px;margin:0 auto 1.5rem;padding:0 1rem;color:#64748b;font-size:.9rem}footer a{color:#1d5fe5}@media(max-width:650px){main{margin:1rem auto}td,th{font-size:.88rem;padding:.5rem}}
</style></head><body><header><strong>Quick Create Proxy SOCKS5 VPN</strong>{{if .CSRF}}<form method="post" action="/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="secondary">Đăng xuất</button></form>{{end}}</header>
<main>{{if .Error}}<p class="error">{{.Error}}</p>{{end}}{{if .Notice}}<p class="notice">{{.Notice}}</p>{{end}}
{{if eq .Title "Đăng nhập"}}
<section class="card" style="max-width:430px;margin:3rem auto"><h1>Đăng nhập quản trị</h1><form method="post" action="/login"><label for="username">Tên đăng nhập</label><input id="username" name="username" value="admin" autocomplete="username" required maxlength="32"><label for="password">Mật khẩu</label><input id="password" name="password" type="password" autocomplete="current-password" required maxlength="72"><p><button type="submit">Đăng nhập</button></p></form><small>Tài khoản ban đầu: admin / 12345687. Hệ thống yêu cầu đổi mật khẩu sau lần đăng nhập đầu tiên.</small></section>
{{else if eq .Title "Đổi mật khẩu"}}
<section class="card" style="max-width:520px;margin:2rem auto"><h1>Đổi mật khẩu quản trị</h1><form method="post" action="/admin/password"><input type="hidden" name="csrf" value="{{.CSRF}}"><label for="current_password">Mật khẩu hiện tại</label><input id="current_password" name="current_password" type="password" autocomplete="current-password" required maxlength="72"><label for="new_password">Mật khẩu mới</label><input id="new_password" name="new_password" type="password" autocomplete="new-password" required minlength="8" maxlength="72"><label for="confirm_password">Nhập lại mật khẩu mới</label><input id="confirm_password" name="confirm_password" type="password" autocomplete="new-password" required minlength="8" maxlength="72"><small>Dùng 8–72 byte và không dùng lại mật khẩu mặc định.</small><p><button type="submit">Lưu mật khẩu mới</button></p></form></section>
{{else if eq .Title "Cập nhật"}}
<section class="card"><h1>Cập nhật phần mềm</h1><p>Phiên bản đang chạy: <strong>v{{.AppVersion}}</strong></p>{{if .Update.Latest}}<p>Phiên bản GitHub Release mới nhất: <strong>v{{.Update.Latest}}</strong>{{if .Update.Prerelease}} (beta){{end}}</p>{{if .Update.Available}}<p>Có phiên bản mới. Dịch vụ sẽ tạm ngắt trong lúc cập nhật.</p><form method="post" action="/update/apply"><input type="hidden" name="csrf" value="{{.CSRF}}"><button>Cập nhật lên phiên bản mới nhất</button></form>{{else}}<p>Đây là phiên bản mới nhất đang có trên GitHub Release.</p>{{end}}{{else}}{{if ne .Update.State.Phase "queued"}}<p>Chưa có bản phát hành nào kèm gói cài đã xác minh trên GitHub.</p>{{end}}{{end}}{{if .Update.State.Phase}}<p>Trạng thái cập nhật: <strong>{{.Update.State.Phase}}</strong> {{.Update.State.Message}}</p>{{end}}<p><a class="button secondary" href="/update/check">Kiểm tra lại</a> <a class="button secondary" href="/">Về tổng quan</a></p></section>
{{else if eq .Title "Thông tin proxy"}}
<section class="card"><h1>Proxy đã được tạo</h1><p>Thông tin đăng nhập này chỉ hiển thị một lần. Hãy lưu vào nơi an toàn.</p><p><strong>{{.Proxy.Kind}}</strong> · cổng {{.Proxy.Port}} · tài khoản {{.Proxy.Username}}</p><div class="secret">Mật khẩu: {{.Password}}</div><p><a class="button" href="/">Về tổng quan</a></p></section>
{{else if eq .Title "Cấu hình WireGuard"}}
<section class="card"><h1>Thiết bị đã được tạo: {{.Peer.Name}}</h1><p>Quét QR trong ứng dụng WireGuard trên iPhone hoặc sao chép cấu hình. Khóa riêng chỉ hiển thị ở trang này; rời trang sẽ không xem lại được.</p><img class="qr" src="{{.QRCode}}" alt="QR WireGuard riêng cho thiết bị"><div class="secret">{{.ClientConfig}}</div><p><a class="button" href="/">Về tổng quan</a></p></section>
{{else if eq .Title "Xác nhận thu hồi"}}
<section class="card"><h1>Thu hồi thiết bị WireGuard?</h1><p>Thiết bị <strong>{{.Peer.Name}}</strong> sẽ mất quyền kết nối ngay. Khóa riêng đã cấp sẽ không thể dùng lại.</p><div class="row"><form method="post" action="/wireguard/peers/{{.Peer.ID}}/delete"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="danger">Thu hồi thiết bị</button></form><a class="button secondary" href="/">Hủy</a></div></section>
{{else if eq .Title "Xác nhận xóa"}}
<section class="card"><h1>Xóa proxy?</h1><p>Bạn sắp xóa <strong>{{.Proxy.Name}}</strong> trên cổng {{.Proxy.Port}}. Kết nối đang dùng sẽ bị ngắt.</p><div class="row"><form method="post" action="/proxies/{{.Proxy.ID}}/delete"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="danger">Xóa proxy</button></form><a class="button secondary" href="/">Hủy</a></div></section>
{{else}}
<h1>Tổng quan</h1><div class="grid"><section class="card"><div class="muted">Proxy đang chạy</div><div class="metric">{{.Status.RunningProxies}}</div></section><section class="card"><div class="muted">Tổng proxy</div><div class="metric">{{.Status.ProxyCount}}</div></section><section class="card"><div class="muted">Thiết bị WireGuard</div><div class="metric">{{len .WireGuard.Peers}}</div></section><section class="card"><div class="muted">Phiên bản</div><div class="metric" style="font-size:1.1rem">{{.Status.Version}}</div></section></div>
<section class="card"><h2>WireGuard VPN</h2>{{if .WireGuard.Initialized}}<p>Endpoint: {{.WireGuard.Endpoint}}:{{.WireGuard.Port}} · {{if .WireGuard.Running}}Đang chạy{{else}}Đã dừng; kiểm tra dịch vụ wg-quick@qcp-wg0{{end}}</p><div class="row">{{if .WireGuard.Running}}<form method="post" action="/wireguard/disable"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="secondary">Dừng VPN</button></form>{{else}}<form method="post" action="/wireguard/enable"><input type="hidden" name="csrf" value="{{.CSRF}}"><button>Bật VPN</button></form>{{end}}</div><form method="post" action="/wireguard/peers"><input type="hidden" name="csrf" value="{{.CSRF}}"><label for="peer_name">Tên thiết bị</label><input id="peer_name" name="name" maxlength="32" required placeholder="iphone-ca-nhan"><label for="peer_mode">Chế độ định tuyến</label><select id="peer_mode" name="mode"><option value="full">Full tunnel (Internet qua VPS)</option><option value="split">Split tunnel (chỉ mạng WireGuard nội bộ)</option></select><p><button type="submit">Tạo thiết bị và hiện QR</button></p></form><div class="scroll"><table><thead><tr><th>Thiết bị</th><th>IP nội bộ</th><th>Chế độ</th><th>Trạng thái</th><th>Handshake gần nhất</th><th>Lưu lượng nhận/gửi</th><th>Thao tác</th></tr></thead><tbody>{{range .WireGuard.Peers}}<tr><td>{{.Name}}</td><td>{{.Address}}</td><td>{{.Mode}}</td><td>{{if .Enabled}}Bật{{else}}Tắt{{end}}</td><td>{{if .LatestHandshake}}{{.LatestHandshake}}{{else}}Chưa có{{end}}</td><td>{{.RXBytes}} / {{.TXBytes}} B</td><td><div class="row">{{if .Enabled}}<form method="post" action="/wireguard/peers/{{.ID}}/disable"><input type="hidden" name="csrf" value="{{$.CSRF}}"><button class="secondary">Tắt</button></form>{{else}}<form method="post" action="/wireguard/peers/{{.ID}}/enable"><input type="hidden" name="csrf" value="{{$.CSRF}}"><button>Bật</button></form>{{end}}<a class="button secondary" href="/wireguard/peers/{{.ID}}/confirm-delete">Thu hồi</a></div></td></tr>{{else}}<tr><td colspan="7" class="muted">Chưa có thiết bị.</td></tr>{{end}}</tbody></table></div>{{else}}<p>Khởi tạo một lần để tạo khóa server. Cần kernel WireGuard, wireguard-tools và nftables. Cổng UDP phải được mở tại nhà cung cấp VPS.</p><form method="post" action="/wireguard"><input type="hidden" name="csrf" value="{{.CSRF}}"><label for="wg_endpoint">IP public hoặc tên miền của VPS</label><input id="wg_endpoint" name="endpoint" required placeholder="203.0.113.10"><label for="wg_port">Cổng UDP</label><input id="wg_port" name="port" type="number" value="51820" min="1024" max="65535" required><p><button type="submit">Khởi tạo WireGuard</button></p></form>{{end}}</section>
<section class="card"><h2>Tạo proxy</h2><form method="post" action="/proxies"><input type="hidden" name="csrf" value="{{.CSRF}}"><label for="kind">Loại</label><select name="kind" id="kind"><option value="socks5">SOCKS5</option><option value="http">HTTP proxy + HTTPS CONNECT</option></select>
<label for="name">Tên</label><input id="name" name="name" required maxlength="64" placeholder="mobile-01"><label for="port">Cổng TCP (10000–19999)</label><input id="port" name="port" type="number" min="10000" max="19999" required>
<label for="username">Tên đăng nhập</label><input id="username" name="username" required maxlength="32" placeholder="user01"><label for="source_cidr">IP nguồn được phép (IPv4 CIDR)</label><input id="source_cidr" name="source_cidr" placeholder="Để trống: chỉ truy cập từ VPS"><small>Ví dụ 203.0.113.4/32. Chọn 0.0.0.0/0 chỉ khi cần truy cập từ mọi IP và đã kiểm tra firewall.</small>
<p><button type="submit">Tạo proxy</button></p></form></section>
<section class="card"><h2>Danh sách proxy</h2><div class="scroll"><table><thead><tr><th>Tên</th><th>Loại</th><th>Cổng</th><th>IP nguồn</th><th>Trạng thái</th><th>Thao tác</th></tr></thead><tbody>{{range .Status.Proxies}}<tr><td>{{.Name}}</td><td>{{.Kind}}</td><td>{{.Port}}</td><td>{{if .SourceCIDR}}{{.SourceCIDR}}{{else}}Chỉ trên VPS{{end}}</td><td>{{if .Running}}Đang chạy{{else}}Đã dừng{{end}}</td><td><div class="row">{{if .Enabled}}<form method="post" action="/proxies/{{.ID}}/disable"><input type="hidden" name="csrf" value="{{$.CSRF}}"><button class="secondary">Dừng</button></form><form method="post" action="/proxies/{{.ID}}/restart"><input type="hidden" name="csrf" value="{{$.CSRF}}"><button class="secondary">Khởi động lại</button></form>{{else}}<form method="post" action="/proxies/{{.ID}}/enable"><input type="hidden" name="csrf" value="{{$.CSRF}}"><button>Kích hoạt</button></form>{{end}}<a class="button secondary" href="/proxies/{{.ID}}/confirm-delete">Xóa</a></div></td></tr>{{else}}<tr><td colspan="6" class="muted">Chưa có proxy.</td></tr>{{end}}</tbody></table></div></section>
{{end}}</main><footer>v{{.AppVersion}}{{if .CSRF}} · <a href="/update/check">Check Update</a> · <a href="/admin/password">Đổi mật khẩu</a>{{end}}</footer></body></html>`))

func runPanel() error {
	if os.Geteuid() == 0 {
		return errors.New("panel must run as the unprivileged qcp user")
	}
	if _, err := os.ReadFile(filepath.Join(etcDir, "admin.hash")); err != nil {
		return fmt.Errorf("admin password is not initialized: %w", err)
	}
	p := &panel{sessions: make(map[string]session), logins: make(map[string]loginBucket)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", p.home)
	mux.HandleFunc("GET /login", p.loginPage)
	mux.HandleFunc("POST /login", p.login)
	mux.HandleFunc("POST /logout", p.logout)
	mux.HandleFunc("GET /admin/password", p.passwordPage)
	mux.HandleFunc("POST /admin/password", p.changePassword)
	mux.HandleFunc("POST /proxies", p.createProxy)
	mux.HandleFunc("POST /wireguard", p.initializeWireGuard)
	mux.HandleFunc("POST /wireguard/{action}", p.wireguardServiceAction)
	mux.HandleFunc("POST /wireguard/peers", p.createWireGuardPeer)
	mux.HandleFunc("POST /wireguard/peers/{id}/{action}", p.wireguardPeerAction)
	mux.HandleFunc("GET /wireguard/peers/{id}/confirm-delete", p.confirmWireGuardDelete)
	mux.HandleFunc("GET /update/check", p.updatePage)
	mux.HandleFunc("POST /update/apply", p.applyUpdate)
	mux.HandleFunc("GET /proxies/{id}/confirm-delete", p.confirmDelete)
	mux.HandleFunc("POST /proxies/{id}/{action}", p.proxyAction)
	server := &http.Server{Addr: panelAddr, Handler: p.secure(mux), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 35 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	log.Printf("qcp panel listening at https://%s", panelAddr)
	return server.ListenAndServeTLS(panelCertPath, panelKeyPath)
}

func (p *panel) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		host := r.Host
		if h, _, err := net.SplitHostPort(r.Host); err == nil {
			host = h
		}
		allowed := host == "127.0.0.1" || host == "localhost" || host == "[::1]" || host == "::1"
		if configured, err := os.ReadFile(panelHostPath); err == nil && host == strings.TrimSpace(string(configured)) {
			allowed = true
		}
		if configured := os.Getenv("QCP_ALLOWED_HOST"); configured != "" && host == configured {
			allowed = true
		}
		if !allowed {
			http.Error(w, "invalid host", http.StatusBadRequest)
			return
		}
		if r.Method == http.MethodPost && !sameOrigin(r) {
			log.Printf("blocked POST with invalid origin: host=%q origin=%q sec-fetch-site=%q sec-fetch-mode=%q remote=%q", r.Host, r.Header.Get("Origin"), r.Header.Get("Sec-Fetch-Site"), r.Header.Get("Sec-Fetch-Mode"), r.RemoteAddr)
			http.Error(w, "Nguồn yêu cầu không hợp lệ. Hãy tải lại trang bằng đúng địa chỉ HTTPS của panel.", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func sameOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	// Chromium can serialize the origin as "null" after the user accepts an
	// exception for a self-signed certificate. Fetch Metadata still identifies
	// a form submission made by this panel as a same-origin navigation. Cross-
	// site and script requests remain rejected.
	if origin == "null" {
		return r.TLS != nil &&
			r.Header.Get("Sec-Fetch-Site") == "same-origin" &&
			r.Header.Get("Sec-Fetch-Mode") == "navigate"
	}
	u, err := url.Parse(origin)
	if err != nil || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || !strings.EqualFold(u.Host, r.Host) {
		return false
	}
	return strings.EqualFold(u.Scheme, "https") && r.TLS != nil
}

func (p *panel) loginPage(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := p.currentSession(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	notice := ""
	if r.URL.Query().Get("changed") == "1" {
		notice = "Đã đổi mật khẩu. Hãy đăng nhập lại."
	}
	p.render(w, pageData{Title: "Đăng nhập", Notice: notice})
}

func (p *panel) login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	remote, _, _ := net.SplitHostPort(r.RemoteAddr)
	if remote == "" {
		remote = r.RemoteAddr
	}
	if p.loginBlocked(remote) {
		p.render(w, pageData{Title: "Đăng nhập", Error: "Đăng nhập tạm thời bị giới hạn. Hãy thử lại sau."})
		return
	}
	hash, err := os.ReadFile(filepath.Join(etcDir, "admin.hash"))
	if err != nil {
		http.Error(w, "admin account unavailable", http.StatusServiceUnavailable)
		return
	}
	if !validAdminLogin(hash, r.PostFormValue("username"), r.PostFormValue("password")) {
		p.recordFailure(remote)
		log.Printf("admin login failed from %s", remote)
		p.render(w, pageData{Title: "Đăng nhập", Error: "Thông tin đăng nhập không đúng."})
		return
	}
	p.clearFailure(remote)
	log.Printf("admin login succeeded from %s", remote)
	token, err := randomToken()
	if err != nil {
		http.Error(w, "session unavailable", http.StatusInternalServerError)
		return
	}
	csrf, err := randomToken()
	if err != nil {
		http.Error(w, "session unavailable", http.StatusInternalServerError)
		return
	}
	now := time.Now()
	p.mu.Lock()
	p.sessions[token] = session{CSRF: csrf, HashEpoch: sha256.Sum256(hash), Created: now, LastSeen: now}
	p.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "qcp_session", Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: cookieSecure(r), MaxAge: 12 * 60 * 60})
	if adminPasswordMustChange() {
		http.Redirect(w, r, "/admin/password", http.StatusSeeOther)
	} else {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func validAdminLogin(hash []byte, username, password string) bool {
	passwordMatches := bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
	return username == "admin" && passwordMatches
}

func (p *panel) loginBlocked(remote string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, key := range []string{remote, "account"} {
		if x, ok := p.logins[key]; ok && time.Now().Before(x.Blocked) {
			return true
		}
	}
	return false
}

func (p *panel) recordFailure(remote string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, key := range []string{remote, "account"} {
		x := p.logins[key]
		if time.Since(x.Started) > 15*time.Minute {
			x = loginBucket{Started: time.Now()}
		}
		x.Failures++
		if x.Failures >= 5 {
			x.Blocked = time.Now().Add(time.Minute)
		}
		p.logins[key] = x
	}
}

func (p *panel) clearFailure(remote string) {
	p.mu.Lock()
	delete(p.logins, remote)
	delete(p.logins, "account")
	p.mu.Unlock()
}

func (p *panel) currentSession(r *http.Request) (string, session, bool) {
	cookie, err := r.Cookie("qcp_session")
	if err != nil || len(cookie.Value) < 32 {
		return "", session{}, false
	}
	hash, err := os.ReadFile(filepath.Join(etcDir, "admin.hash"))
	if err != nil {
		return "", session{}, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.sessions[cookie.Value]
	if !ok || time.Since(s.LastSeen) > 30*time.Minute || time.Since(s.Created) > 12*time.Hour || s.HashEpoch != sha256.Sum256(hash) {
		delete(p.sessions, cookie.Value)
		return "", session{}, false
	}
	s.LastSeen = time.Now()
	p.sessions[cookie.Value] = s
	return cookie.Value, s, true
}

func (p *panel) requireSession(w http.ResponseWriter, r *http.Request, csrf bool) (session, bool) {
	_, s, ok := p.currentSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return session{}, false
	}
	if adminPasswordMustChange() && r.URL.Path != "/admin/password" && r.URL.Path != "/logout" {
		http.Redirect(w, r, "/admin/password", http.StatusSeeOther)
		return session{}, false
	}
	if csrf {
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil || r.PostFormValue("csrf") != s.CSRF {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return session{}, false
		}
	}
	return s, true
}

func adminPasswordMustChange() bool {
	_, err := os.Stat(adminMustChangePath)
	return err == nil
}

func (p *panel) passwordPage(w http.ResponseWriter, r *http.Request) {
	s, ok := p.requireSession(w, r, false)
	if !ok {
		return
	}
	notice := "Bạn có thể đổi mật khẩu quản trị tại đây."
	if adminPasswordMustChange() {
		notice = "Bạn phải đổi mật khẩu mặc định trước khi sử dụng panel."
	}
	p.render(w, pageData{Title: "Đổi mật khẩu", CSRF: s.CSRF, Notice: notice})
}

func (p *panel) changePassword(w http.ResponseWriter, r *http.Request) {
	s, ok := p.requireSession(w, r, true)
	if !ok {
		return
	}
	current := r.PostFormValue("current_password")
	newPassword := r.PostFormValue("new_password")
	if newPassword != r.PostFormValue("confirm_password") {
		p.render(w, pageData{Title: "Đổi mật khẩu", CSRF: s.CSRF, Error: "Mật khẩu nhập lại không khớp."})
		return
	}
	request := changeAdminPasswordRequest{CurrentPassword: current, NewPassword: newPassword}
	if err := agentRequest(http.MethodPost, "/v1/admin/password", request, nil); err != nil {
		p.render(w, pageData{Title: "Đổi mật khẩu", CSRF: s.CSRF, Error: err.Error()})
		return
	}
	if cookie, err := r.Cookie("qcp_session"); err == nil {
		p.mu.Lock()
		delete(p.sessions, cookie.Value)
		p.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "qcp_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: cookieSecure(r)})
	http.Redirect(w, r, "/login?changed=1", http.StatusSeeOther)
}

func (p *panel) home(w http.ResponseWriter, r *http.Request) {
	s, ok := p.requireSession(w, r, false)
	if !ok {
		return
	}
	var data pageData
	data.Title = "Tổng quan"
	data.CSRF = s.CSRF
	data.Notice = r.URL.Query().Get("notice")
	if err := agentRequest(http.MethodGet, "/v1/status", nil, &data.Status); err != nil {
		data.Error = "Dịch vụ quản trị chưa sẵn sàng: " + err.Error()
	}
	if err := agentRequest(http.MethodGet, "/v1/wireguard", nil, &data.WireGuard); err != nil {
		data.Error = "WireGuard chưa sẵn sàng: " + err.Error()
	}
	p.render(w, data)
}

func (p *panel) updatePage(w http.ResponseWriter, r *http.Request) {
	s, ok := p.requireSession(w, r, false)
	if !ok {
		return
	}
	data := pageData{Title: "Cập nhật", CSRF: s.CSRF, Notice: r.URL.Query().Get("notice")}
	if err := agentRequest(http.MethodGet, "/v1/update", nil, &data.Update); err != nil {
		data.Error = "Không kiểm tra được GitHub Release: " + err.Error()
	}
	p.render(w, data)
}

func (p *panel) applyUpdate(w http.ResponseWriter, r *http.Request) {
	s, ok := p.requireSession(w, r, true)
	if !ok {
		return
	}
	data := pageData{Title: "Cập nhật", CSRF: s.CSRF}
	if err := agentRequest(http.MethodPost, "/v1/update", nil, nil); err != nil {
		data.Error = "Không bắt đầu được cập nhật: " + err.Error()
	} else {
		data.Notice = "Đã bắt đầu cập nhật. Panel có thể tạm ngắt; chờ một phút rồi kiểm tra lại."
		data.Update.State.Phase = "queued"
	}
	p.render(w, data)
}

func (p *panel) createProxy(w http.ResponseWriter, r *http.Request) {
	s, ok := p.requireSession(w, r, true)
	if !ok {
		return
	}
	port, err := strconv.Atoi(r.PostFormValue("port"))
	if err != nil {
		http.Error(w, "invalid port", http.StatusBadRequest)
		return
	}
	input := createProxyRequest{Name: r.PostFormValue("name"), Kind: r.PostFormValue("kind"), Port: port, Username: r.PostFormValue("username"), SourceCIDR: strings.TrimSpace(r.PostFormValue("source_cidr"))}
	var result createProxyResponse
	if err := agentRequest(http.MethodPost, "/v1/proxies", input, &result); err != nil {
		http.Redirect(w, r, "/?notice="+url.QueryEscape("Tạo proxy lỗi: "+err.Error()), http.StatusSeeOther)
		return
	}
	p.render(w, pageData{Title: "Thông tin proxy", CSRF: s.CSRF, Proxy: result.Proxy, Password: result.Password})
}

func (p *panel) initializeWireGuard(w http.ResponseWriter, r *http.Request) {
	_, ok := p.requireSession(w, r, true)
	if !ok {
		return
	}
	port, err := strconv.Atoi(r.PostFormValue("port"))
	if err != nil {
		http.Error(w, "invalid port", http.StatusBadRequest)
		return
	}
	var result wireguardView
	err = agentRequest(http.MethodPost, "/v1/wireguard", wireguardInitRequest{Endpoint: strings.TrimSpace(r.PostFormValue("endpoint")), Port: port}, &result)
	if err != nil {
		http.Redirect(w, r, "/?notice="+url.QueryEscape("WireGuard: "+err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?notice="+url.QueryEscape("WireGuard đã khởi tạo."), http.StatusSeeOther)
}

func (p *panel) createWireGuardPeer(w http.ResponseWriter, r *http.Request) {
	s, ok := p.requireSession(w, r, true)
	if !ok {
		return
	}
	var result createPeerResponse
	if err := agentRequest(http.MethodPost, "/v1/wireguard/peers", createPeerRequest{Name: r.PostFormValue("name"), Mode: r.PostFormValue("mode")}, &result); err != nil {
		http.Redirect(w, r, "/?notice="+url.QueryEscape("Tạo thiết bị lỗi: "+err.Error()), http.StatusSeeOther)
		return
	}
	png, err := qrcode.Encode(result.ClientConfig, qrcode.Medium, 280)
	if err != nil {
		http.Error(w, "QR generation failed", http.StatusInternalServerError)
		return
	}
	p.render(w, pageData{Title: "Cấu hình WireGuard", CSRF: s.CSRF, Peer: result.Peer, ClientConfig: result.ClientConfig, QRCode: template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png))})
}

func (p *panel) wireguardPeerAction(w http.ResponseWriter, r *http.Request) {
	if _, ok := p.requireSession(w, r, true); !ok {
		return
	}
	id := r.PathValue("id")
	if !validID.MatchString(id) {
		http.Error(w, "invalid peer ID", http.StatusBadRequest)
		return
	}
	action := r.PathValue("action")
	if action != "enable" && action != "disable" && action != "delete" {
		http.NotFound(w, r)
		return
	}
	method := http.MethodPost
	path := "/v1/wireguard/peers/" + id + "/" + action
	if action == "delete" {
		method = http.MethodDelete
		path = "/v1/wireguard/peers/" + id
	}
	if err := agentRequest(method, path, nil, nil); err != nil {
		http.Redirect(w, r, "/?notice="+url.QueryEscape("WireGuard: "+err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?notice="+url.QueryEscape("Đã cập nhật thiết bị WireGuard."), http.StatusSeeOther)
}

func (p *panel) wireguardServiceAction(w http.ResponseWriter, r *http.Request) {
	if _, ok := p.requireSession(w, r, true); !ok {
		return
	}
	action := r.PathValue("action")
	if action != "enable" && action != "disable" {
		http.NotFound(w, r)
		return
	}
	if err := agentRequest(http.MethodPost, "/v1/wireguard/"+action, nil, nil); err != nil {
		http.Redirect(w, r, "/?notice="+url.QueryEscape("WireGuard: "+err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?notice="+url.QueryEscape("Đã cập nhật dịch vụ WireGuard."), http.StatusSeeOther)
}

func (p *panel) confirmWireGuardDelete(w http.ResponseWriter, r *http.Request) {
	s, ok := p.requireSession(w, r, false)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if !validID.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	var data wireguardView
	if err := agentRequest(http.MethodGet, "/v1/wireguard", nil, &data); err != nil {
		http.Error(w, "WireGuard unavailable", http.StatusServiceUnavailable)
		return
	}
	for _, peer := range data.Peers {
		if peer.ID == id {
			p.render(w, pageData{Title: "Xác nhận thu hồi", CSRF: s.CSRF, Peer: peer})
			return
		}
	}
	http.NotFound(w, r)
}

func (p *panel) proxyAction(w http.ResponseWriter, r *http.Request) {
	if _, ok := p.requireSession(w, r, true); !ok {
		return
	}
	id := r.PathValue("id")
	if !validID.MatchString(id) {
		http.Error(w, "invalid proxy ID", http.StatusBadRequest)
		return
	}
	action := r.PathValue("action")
	method := http.MethodPost
	if action != "enable" && action != "disable" && action != "restart" && action != "delete" {
		http.NotFound(w, r)
		return
	}
	path := "/v1/proxies/" + id
	if action == "delete" {
		method = http.MethodDelete
	} else {
		path += "/" + action
	}
	if err := agentRequest(method, path, nil, nil); err != nil {
		http.Redirect(w, r, "/?notice="+url.QueryEscape("Thao tác lỗi: "+err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?notice="+url.QueryEscape("Đã "+map[string]string{"enable": "kích hoạt", "disable": "dừng", "restart": "khởi động lại", "delete": "xóa"}[action]+" proxy."), http.StatusSeeOther)
}

func (p *panel) confirmDelete(w http.ResponseWriter, r *http.Request) {
	s, ok := p.requireSession(w, r, false)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if !validID.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	var list []proxyView
	if err := agentRequest(http.MethodGet, "/v1/proxies", nil, &list); err != nil {
		http.Error(w, "proxy list unavailable", http.StatusServiceUnavailable)
		return
	}
	for _, item := range list {
		if item.ID == id {
			p.render(w, pageData{Title: "Xác nhận xóa", CSRF: s.CSRF, Proxy: item})
			return
		}
	}
	http.NotFound(w, r)
}

func (p *panel) logout(w http.ResponseWriter, r *http.Request) {
	if _, ok := p.requireSession(w, r, true); !ok {
		return
	}
	if cookie, err := r.Cookie("qcp_session"); err == nil {
		p.mu.Lock()
		delete(p.sessions, cookie.Value)
		p.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "qcp_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: cookieSecure(r)})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (p *panel) render(w http.ResponseWriter, data pageData) {
	data.AppVersion = version
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := basePage.Execute(w, data); err != nil {
		log.Printf("template error: %v", err)
	}
}

func cookieSecure(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
