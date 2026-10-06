package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const panelFirewallStatePath = stateDir + "/panel-firewall.json"
const proxyFirewallStateDir = stateDir + "/proxy-firewalls"

type panelFirewallState struct {
	Backend string `json:"backend"`
	Zone    string `json:"zone,omitempty"`
	Added   bool   `json:"added"`
	Port    int    `json:"port,omitempty"`
	Comment string `json:"comment,omitempty"`
}

func (state panelFirewallState) normalized() panelFirewallState {
	if state.Port == 0 {
		state.Port = 22689
	}
	if state.Comment == "" {
		state.Comment = "QCP-panel"
	}
	return state
}

func panelFirewall(action string) error {
	if err := mustRoot(); err != nil {
		return err
	}
	if action == "down" {
		return closePanelPort()
	}
	if action != "up" {
		return errors.New("invalid firewall action")
	}
	if state, err := loadPanelFirewallState(); err == nil {
		return applyPanelFirewallState(state)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	state, err := detectAndOpenTCPPort(22689, "QCP-panel")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return err
	}
	b, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err := atomicWrite(panelFirewallStatePath, b, 0600, 0, 0); err != nil {
		if state.Added {
			_ = removePanelFirewallState(state)
		}
		return err
	}
	fmt.Printf("Panel firewall: %s (TCP 22689 accessible at host firewall)\n", state.Backend)
	return nil
}

func loadPanelFirewallState() (panelFirewallState, error) {
	var state panelFirewallState
	b, err := os.ReadFile(panelFirewallStatePath)
	if err != nil {
		return state, err
	}
	if err := json.Unmarshal(b, &state); err != nil {
		return state, err
	}
	return state, nil
}

func commandOutput(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return strings.TrimSpace(string(out)), fmt.Errorf("%s %s: %s: %w", name, strings.Join(args, " "), strings.TrimSpace(string(out)), err)
	}
	return strings.TrimSpace(string(out)), nil
}

func commandOK(name string, args ...string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Run() == nil
}

func detectAndOpenTCPPort(port int, comment string) (panelFirewallState, error) {
	portSpec := fmt.Sprintf("%d/tcp", port)
	if _, err := exec.LookPath("ufw"); err == nil {
		status, statusErr := commandOutput("ufw", "status")
		if statusErr == nil && strings.HasPrefix(strings.ToLower(status), "status: active") {
			if ufwAllowsTCPPort(status, port) {
				return panelFirewallState{Backend: "ufw", Added: false, Port: port, Comment: comment}, nil
			}
			if _, err := commandOutput("ufw", "allow", portSpec, "comment", comment); err != nil {
				return panelFirewallState{}, err
			}
			return panelFirewallState{Backend: "ufw", Added: true, Port: port, Comment: comment}, nil
		}
	}
	if _, err := exec.LookPath("firewall-cmd"); err == nil && commandOK("firewall-cmd", "--state") {
		zone, err := commandOutput("firewall-cmd", "--get-default-zone")
		if err != nil {
			return panelFirewallState{}, err
		}
		state := panelFirewallState{Backend: "firewalld", Zone: zone, Port: port, Comment: comment}
		if commandOK("firewall-cmd", "--zone="+zone, "--query-port="+portSpec) {
			return state, nil
		}
		if _, err := commandOutput("firewall-cmd", "--permanent", "--zone="+zone, "--add-port="+portSpec); err != nil {
			return panelFirewallState{}, err
		}
		if _, err := commandOutput("firewall-cmd", "--zone="+zone, "--add-port="+portSpec); err != nil {
			_, _ = commandOutput("firewall-cmd", "--permanent", "--zone="+zone, "--remove-port="+portSpec)
			return panelFirewallState{}, err
		}
		state.Added = true
		return state, nil
	}
	if _, err := exec.LookPath("iptables"); err == nil {
		args := []string{"INPUT", "-p", "tcp", "--dport", strconv.Itoa(port), "-m", "comment", "--comment", comment, "-j", "ACCEPT"}
		if commandOK("iptables", append([]string{"-C"}, args...)...) {
			return panelFirewallState{Backend: "iptables", Added: false, Port: port, Comment: comment}, nil
		}
		if _, err := commandOutput("iptables", append([]string{"-I"}, args...)...); err != nil {
			return panelFirewallState{}, err
		}
		return panelFirewallState{Backend: "iptables", Added: true, Port: port, Comment: comment}, nil
	}
	return panelFirewallState{Backend: "none", Added: false, Port: port, Comment: comment}, nil
}

func applyPanelFirewallState(state panelFirewallState) error {
	state = state.normalized()
	if !state.Added {
		return nil
	}
	portSpec := fmt.Sprintf("%d/tcp", state.Port)
	switch state.Backend {
	case "ufw":
		if !commandOK("ufw", "status") {
			return errors.New("UFW recorded for QCP but is unavailable")
		}
		if output, _ := commandOutput("ufw", "status"); ufwAllowsTCPPort(output, state.Port) {
			return nil
		}
		_, err := commandOutput("ufw", "allow", portSpec, "comment", state.Comment)
		return err
	case "firewalld":
		if !commandOK("firewall-cmd", "--state") {
			return errors.New("firewalld recorded for QCP but is not running")
		}
		if !commandOK("firewall-cmd", "--permanent", "--zone="+state.Zone, "--query-port="+portSpec) {
			if _, err := commandOutput("firewall-cmd", "--permanent", "--zone="+state.Zone, "--add-port="+portSpec); err != nil {
				return err
			}
		}
		if !commandOK("firewall-cmd", "--zone="+state.Zone, "--query-port="+portSpec) {
			_, err := commandOutput("firewall-cmd", "--zone="+state.Zone, "--add-port="+portSpec)
			return err
		}
		return nil
	case "iptables":
		args := []string{"INPUT", "-p", "tcp", "--dport", strconv.Itoa(state.Port), "-m", "comment", "--comment", state.Comment, "-j", "ACCEPT"}
		if commandOK("iptables", append([]string{"-C"}, args...)...) {
			return nil
		}
		_, err := commandOutput("iptables", append([]string{"-I"}, args...)...)
		return err
	case "none":
		return nil
	default:
		return errors.New("invalid stored firewall backend")
	}
}

func ufwAllowsPanel(status string) bool {
	return ufwAllowsTCPPort(status, 22689)
}

func ufwAllowsTCPPort(status string, port int) bool {
	want := fmt.Sprintf("%d/tcp", port)
	for _, line := range strings.Split(status, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.EqualFold(fields[0], want) && strings.EqualFold(fields[1], "ALLOW") {
			return true
		}
	}
	return false
}

func closePanelPort() error {
	state, err := loadPanelFirewallState()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if state.Added {
		if err := removePanelFirewallState(state); err != nil {
			return err
		}
	}
	return os.Remove(panelFirewallStatePath)
}

func removePanelFirewallState(state panelFirewallState) error {
	state = state.normalized()
	portSpec := fmt.Sprintf("%d/tcp", state.Port)
	switch state.Backend {
	case "ufw":
		_, err := commandOutput("ufw", "delete", "allow", portSpec, "comment", state.Comment)
		return err
	case "firewalld":
		_, runtimeErr := commandOutput("firewall-cmd", "--zone="+state.Zone, "--remove-port="+portSpec)
		_, permanentErr := commandOutput("firewall-cmd", "--permanent", "--zone="+state.Zone, "--remove-port="+portSpec)
		if runtimeErr != nil {
			return runtimeErr
		}
		return permanentErr
	case "iptables":
		args := []string{"INPUT", "-p", "tcp", "--dport", strconv.Itoa(state.Port), "-m", "comment", "--comment", state.Comment, "-j", "ACCEPT"}
		if !commandOK("iptables", append([]string{"-C"}, args...)...) {
			return nil
		}
		_, err := commandOutput("iptables", append([]string{"-D"}, args...)...)
		return err
	case "none":
		return nil
	default:
		return errors.New("invalid stored firewall backend")
	}
}

func proxyFirewallStatePath(id string) string {
	return filepath.Join(proxyFirewallStateDir, id+".json")
}

func ensureProxyFirewall(id string, port int) error {
	if !validID.MatchString(id) || port < 10000 || port > 19999 {
		return errors.New("invalid proxy firewall identity or port")
	}
	path := proxyFirewallStatePath(id)
	var state panelFirewallState
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, &state); err != nil {
			return err
		}
		state = state.normalized()
		if state.Port != port {
			return errors.New("stored proxy firewall port does not match proxy")
		}
		return applyPanelFirewallState(state)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	state, err := detectAndOpenTCPPort(port, "QCP-proxy-"+id)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(proxyFirewallStateDir, 0700); err != nil {
		if state.Added {
			_ = removePanelFirewallState(state)
		}
		return err
	}
	b, err := json.Marshal(state)
	if err == nil {
		err = atomicWrite(path, b, 0600, 0, 0)
	}
	if err != nil && state.Added {
		_ = removePanelFirewallState(state)
	}
	return err
}

func removeProxyFirewall(id string) error {
	if !validID.MatchString(id) {
		return errors.New("invalid proxy firewall identity")
	}
	path := proxyFirewallStatePath(id)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var state panelFirewallState
	if err := json.Unmarshal(b, &state); err != nil {
		return err
	}
	if state.Added {
		if err := removePanelFirewallState(state); err != nil {
			return err
		}
	}
	return os.Remove(path)
}

func removeAllProxyFirewalls() error {
	entries, err := os.ReadDir(proxyFirewallStateDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := strings.TrimSuffix(entry.Name(), ".json")
		if entry.IsDir() || !validID.MatchString(name) {
			continue
		}
		if err := removeProxyFirewall(name); err != nil {
			return err
		}
	}
	return nil
}
