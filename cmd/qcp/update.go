package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const githubRepo = "hgn389/Quick-create-Proxy-Socks5-VPN"
const githubReleasesAPI = "https://api.github.com/repos/" + githubRepo + "/releases"
const maxUpdateArchive = 128 << 20
const maxUpdateUnpacked = 384 << 20
const updateStatusPath = stateDir + "/update-status.json"
const updateLockPath = stateDir + "/update.lock"

var releaseTagRE = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$`)
var sha256RE = regexp.MustCompile(`^[a-f0-9]{64}$`)

type githubAsset struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
	State  string `json:"state"`
}
type githubRelease struct {
	TagName    string        `json:"tag_name"`
	Draft      bool          `json:"draft"`
	Prerelease bool          `json:"prerelease"`
	Assets     []githubAsset `json:"assets"`
}
type updateState struct {
	Phase     string `json:"phase"`
	Version   string `json:"version,omitempty"`
	Message   string `json:"message,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}
type updateView struct {
	Current    string      `json:"current"`
	Latest     string      `json:"latest,omitempty"`
	Available  bool        `json:"available"`
	Prerelease bool        `json:"prerelease,omitempty"`
	State      updateState `json:"state"`
}

func versionParts(tag string) ([]int, string, bool) {
	match := releaseTagRE.FindStringSubmatch(tag)
	if match == nil {
		return nil, "", false
	}
	parts := make([]int, 3)
	for i := range parts {
		n, err := strconv.Atoi(match[i+1])
		if err != nil {
			return nil, "", false
		}
		parts[i] = n
	}
	for _, identifier := range strings.Split(match[4], ".") {
		if len(identifier) > 1 && identifier[0] == '0' {
			if _, err := strconv.ParseUint(identifier, 10, 64); err == nil {
				return nil, "", false
			}
		}
	}
	return parts, match[4], true
}
func comparePrerelease(a, b string) int {
	if a == b {
		return 0
	}
	if a == "" {
		return 1
	}
	if b == "" {
		return -1
	}
	x, y := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] == y[i] {
			continue
		}
		ai, ae := strconv.ParseUint(x[i], 10, 64)
		bi, be := strconv.ParseUint(y[i], 10, 64)
		if ae == nil && be != nil {
			return -1
		}
		if ae != nil && be == nil {
			return 1
		}
		if ae == nil && be == nil {
			if ai < bi {
				return -1
			}
			return 1
		}
		if x[i] < y[i] {
			return -1
		}
		return 1
	}
	if len(x) < len(y) {
		return -1
	}
	return 1
}
func compareVersions(a, b string) (int, error) {
	av, ap, ok := versionParts(a)
	if !ok {
		return 0, fmt.Errorf("invalid release version %q", a)
	}
	bv, bp, ok := versionParts(b)
	if !ok {
		return 0, fmt.Errorf("invalid release version %q", b)
	}
	for i := range av {
		if av[i] < bv[i] {
			return -1, nil
		}
		if av[i] > bv[i] {
			return 1, nil
		}
	}
	return comparePrerelease(ap, bp), nil
}
func expectedReleaseAsset(tag string) string { return "qcp-" + tag + "-linux-amd64-arm64.tar.gz" }
func assetForRelease(release githubRelease) (githubAsset, bool) {
	name := expectedReleaseAsset(release.TagName)
	for _, asset := range release.Assets {
		if asset.Name == name && asset.State == "uploaded" && asset.Size > 0 && asset.Size <= maxUpdateArchive && strings.HasPrefix(asset.Digest, "sha256:") && sha256RE.MatchString(strings.TrimPrefix(asset.Digest, "sha256:")) {
			return asset, true
		}
	}
	return githubAsset{}, false
}
func githubHTTP(ctx context.Context, url string, maxBytes int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "qcp/"+version)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, errors.New("GitHub response is too large")
	}
	return body, nil
}
func listGithubReleases(ctx context.Context) ([]githubRelease, error) {
	body, err := githubHTTP(ctx, githubReleasesAPI+"?per_page=100", 2<<20)
	if err != nil {
		return nil, err
	}
	var releases []githubRelease
	if err := json.Unmarshal(body, &releases); err != nil {
		return nil, err
	}
	return releases, nil
}
func latestRelease(ctx context.Context) (githubRelease, githubAsset, bool, error) {
	releases, err := listGithubReleases(ctx)
	if err != nil {
		return githubRelease{}, githubAsset{}, false, err
	}
	var latest githubRelease
	var asset githubAsset
	found := false
	for _, item := range releases {
		if item.Draft {
			continue
		}
		if _, _, ok := versionParts(item.TagName); !ok {
			continue
		}
		candidate, ok := assetForRelease(item)
		if !ok {
			continue
		}
		if !found {
			latest = item
			asset = candidate
			found = true
			continue
		}
		cmp, _ := compareVersions(item.TagName, latest.TagName)
		if cmp > 0 {
			latest = item
			asset = candidate
		}
	}
	return latest, asset, found, nil
}
func readUpdateState() updateState {
	var state updateState
	b, err := os.ReadFile(updateStatusPath)
	if err == nil {
		_ = json.Unmarshal(b, &state)
	}
	return state
}
func writeUpdateState(phase, tag, message string) error {
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return err
	}
	b, err := json.Marshal(updateState{Phase: phase, Version: tag, Message: message, UpdatedAt: time.Now().UTC().Format(time.RFC3339)})
	if err != nil {
		return err
	}
	return atomicWrite(updateStatusPath, b, 0600, 0, 0)
}
func updaterLockHeld() bool {
	lock, err := os.OpenFile(updateLockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return true
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return true
	}
	_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return false
}
func (a *agent) checkUpdate(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	release, _, found, err := latestRelease(ctx)
	if err != nil {
		apiError(w, fmt.Errorf("cannot check GitHub Releases: %w", err), http.StatusBadGateway)
		return
	}
	v := updateView{Current: version, State: readUpdateState()}
	if found {
		v.Latest = strings.TrimPrefix(release.TagName, "v")
		v.Prerelease = release.Prerelease
		cmp, _ := compareVersions(release.TagName, "v"+version)
		v.Available = cmp > 0
	}
	apiJSON(w, v)
}
func (a *agent) startUpdate(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := os.Stat(filepath.Join(etcDir, "admin.hash")); err != nil {
		apiError(w, errors.New("admin account is not initialized"), 409)
		return
	}
	current := readUpdateState()
	if current.Phase == "queued" || current.Phase == "downloading" || current.Phase == "installing" {
		queuedAt, _ := time.Parse(time.RFC3339, current.UpdatedAt)
		if (current.Phase == "queued" && time.Since(queuedAt) < 2*time.Minute) || updaterLockHeld() {
			apiError(w, errors.New("an update is already running"), 409)
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	release, _, found, err := latestRelease(ctx)
	if err != nil {
		apiError(w, err, 502)
		return
	}
	if !found {
		apiError(w, errors.New("no verified release asset is available"), 409)
		return
	}
	cmp, _ := compareVersions(release.TagName, "v"+version)
	if cmp <= 0 {
		apiError(w, errors.New("this installation is already current"), 409)
		return
	}
	if err := writeUpdateState("queued", release.TagName, "Preparing update"); err != nil {
		apiError(w, err, 500)
		return
	}
	unit := "qcp-update-" + time.Now().UTC().Format("20060102T150405")
	cmd := exec.CommandContext(ctx, "systemd-run", "--collect", "--unit="+unit, "/usr/local/bin/qcp", "update", "apply", release.TagName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		_ = writeUpdateState("failed", release.TagName, "Unable to start updater")
		apiError(w, fmt.Errorf("systemd-run: %s: %w", strings.TrimSpace(string(out)), err), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(readUpdateState())
}
func updateCLI(tag string) (err error) {
	if err := mustRoot(); err != nil {
		return err
	}
	if _, _, ok := versionParts(tag); !ok {
		return errors.New("invalid update tag")
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(updateLockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("another update is running")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	defer func() {
		if err != nil {
			_ = writeUpdateState("failed", tag, "Update failed; inspect journalctl -u 'qcp-update-*' for details")
		}
	}()
	if err = writeUpdateState("downloading", tag, "Downloading GitHub release"); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	releases, e := listGithubReleases(ctx)
	if e != nil {
		return e
	}
	var asset githubAsset
	found := false
	for _, item := range releases {
		if item.TagName == tag && !item.Draft {
			if candidate, ok := assetForRelease(item); ok {
				asset = candidate
				found = true
			}
			break
		}
	}
	if !found {
		return errors.New("release or SHA256 digest is unavailable")
	}
	cmp, e := compareVersions(tag, "v"+version)
	if e != nil || cmp <= 0 {
		return errors.New("release is not newer than installed version")
	}
	archivePath, e := downloadRelease(ctx, tag, asset)
	if e != nil {
		return e
	}
	defer os.Remove(archivePath)
	stage, e := os.MkdirTemp(stateDir, "update-stage-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(stage)
	root, e := extractRelease(archivePath, stage, tag)
	if e != nil {
		return e
	}
	versionFile, e := os.ReadFile(filepath.Join(root, "VERSION"))
	if e != nil {
		return e
	}
	if strings.TrimSpace(string(versionFile)) != strings.TrimPrefix(tag, "v") {
		return errors.New("release VERSION does not match tag")
	}
	if err = writeUpdateState("installing", tag, "Installing verified release"); err != nil {
		return err
	}
	cmd := exec.Command("bash", "install.sh", "--install", "--yes")
	cmd.Dir = root
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	host, e := os.ReadFile(panelHostPath)
	if e != nil {
		return e
	}
	cmd.Env = append(os.Environ(), "QCP_PANEL_IP="+strings.TrimSpace(string(host)))
	if err = cmd.Run(); err != nil {
		return fmt.Errorf("installer failed: %w", err)
	}
	return writeUpdateState("success", tag, "Update installed successfully")
}
func downloadRelease(ctx context.Context, tag string, asset githubAsset) (string, error) {
	url := "https://github.com/" + githubRepo + "/releases/download/" + tag + "/" + expectedReleaseAsset(tag)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "qcp/"+version)
	client := &http.Client{Timeout: 4 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("release download returned HTTP %d", resp.StatusCode)
	}
	file, err := os.CreateTemp(stateDir, "update-*.tar.gz")
	if err != nil {
		return "", err
	}
	path := file.Name()
	success := false
	defer func() {
		_ = file.Close()
		if !success {
			_ = os.Remove(path)
		}
	}()
	hash := sha256.New()
	count, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(resp.Body, maxUpdateArchive+1))
	if copyErr != nil {
		return "", copyErr
	}
	if count != asset.Size || count > maxUpdateArchive {
		return "", errors.New("release asset size mismatch")
	}
	if !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), strings.TrimPrefix(asset.Digest, "sha256:")) {
		return "", errors.New("GitHub release SHA256 mismatch")
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	success = true
	return path, nil
}
func extractRelease(archivePath, stage, tag string) (string, error) {
	file, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return "", err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	prefix := "qcp-" + tag + "/"
	root := filepath.Join(stage, "qcp-"+tag)
	var total int64
	entries := 0
	for {
		h, e := tr.Next()
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return "", e
		}
		entries++
		if entries > 1000 {
			return "", errors.New("too many archive entries")
		}
		name := strings.TrimPrefix(h.Name, "./")
		if (name == strings.TrimSuffix(prefix, "/") || name == prefix) && h.Typeflag == tar.TypeDir {
			continue
		}
		if !strings.HasPrefix(name, prefix) {
			return "", errors.New("unexpected release archive path")
		}
		rel := strings.TrimSuffix(strings.TrimPrefix(name, prefix), "/")
		clean := filepath.Clean(rel)
		if rel == "" || clean != rel || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || filepath.IsAbs(clean) {
			return "", errors.New("unsafe archive path")
		}
		target := filepath.Join(root, clean)
		if !strings.HasPrefix(target, root+string(os.PathSeparator)) {
			return "", errors.New("archive path escapes staging directory")
		}
		if h.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(target, 0755); err != nil {
				return "", err
			}
			continue
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			return "", errors.New("release archive contains non-regular file")
		}
		if h.Size < 0 || h.Size > 64<<20 {
			return "", errors.New("release archive entry is too large")
		}
		total += h.Size
		if total > maxUpdateUnpacked {
			return "", errors.New("release archive is too large")
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return "", err
		}
		output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return "", err
		}
		_, err = io.CopyN(output, tr, h.Size)
		closeErr := output.Close()
		if err != nil {
			return "", err
		}
		if closeErr != nil {
			return "", closeErr
		}
		if err := os.Chmod(target, os.FileMode(h.Mode)&0755); err != nil {
			return "", err
		}
	}
	for _, name := range []string{"install.sh", "VERSION", "dist/go/SHA256SUMS", "dist/vendor/3proxy/SHA256SUMS"} {
		if _, err := os.Stat(filepath.Join(root, name)); err != nil {
			return "", fmt.Errorf("release is missing %s", name)
		}
	}
	return root, nil
}
