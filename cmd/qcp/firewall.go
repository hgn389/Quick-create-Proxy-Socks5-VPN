package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const panelFirewallStatePath = stateDir + "/panel-firewall.json"

type panelFirewallState struct {
	Backend string `json:"backend"`
	Zone    string `json:"zone,omitempty"`
	Added   bool   `json:"added"`
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
	state, err := detectAndOpenPanelPort()
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

func detectAndOpenPanelPort() (panelFirewallState, error) {
	if _, err := exec.LookPath("ufw"); err == nil {
		status, statusErr := commandOutput("ufw", "status")
		if statusErr == nil && strings.HasPrefix(strings.ToLower(status), "status: active") {
			if ufwAllowsPanel(status) {
				return panelFirewallState{Backend: "ufw", Added: false}, nil
			}
			if _, err := commandOutput("ufw", "allow", "22689/tcp", "comment", "QCP-panel"); err != nil {
				return panelFirewallState{}, err
			}
			return panelFirewallState{Backend: "ufw", Added: true}, nil
		}
	}
	if _, err := exec.LookPath("firewall-cmd"); err == nil && commandOK("firewall-cmd", "--state") {
		zone, err := commandOutput("firewall-cmd", "--get-default-zone")
		if err != nil {
			return panelFirewallState{}, err
		}
		state := panelFirewallState{Backend: "firewalld", Zone: zone}
		if commandOK("firewall-cmd", "--zone="+zone, "--query-port=22689/tcp") {
			return state, nil
		}
		if _, err := commandOutput("firewall-cmd", "--permanent", "--zone="+zone, "--add-port=22689/tcp"); err != nil {
			return panelFirewallState{}, err
		}
		if _, err := commandOutput("firewall-cmd", "--zone="+zone, "--add-port=22689/tcp"); err != nil {
			_, _ = commandOutput("firewall-cmd", "--permanent", "--zone="+zone, "--remove-port=22689/tcp")
			return panelFirewallState{}, err
		}
		state.Added = true
		return state, nil
	}
	if _, err := exec.LookPath("iptables"); err == nil {
		args := []string{"INPUT", "-p", "tcp", "--dport", "22689", "-m", "comment", "--comment", "QCP-panel", "-j", "ACCEPT"}
		if commandOK("iptables", append([]string{"-C"}, args...)...) {
			return panelFirewallState{Backend: "iptables", Added: false}, nil
		}
		if _, err := commandOutput("iptables", append([]string{"-I"}, args...)...); err != nil {
			return panelFirewallState{}, err
		}
		return panelFirewallState{Backend: "iptables", Added: true}, nil
	}
	return panelFirewallState{Backend: "none", Added: false}, nil
}

func applyPanelFirewallState(state panelFirewallState) error {
	if !state.Added {
		return nil
	}
	switch state.Backend {
	case "ufw":
		if !commandOK("ufw", "status") {
			return errors.New("UFW recorded for QCP but is unavailable")
		}
		if output, _ := commandOutput("ufw", "status"); ufwAllowsPanel(output) {
			return nil
		}
		_, err := commandOutput("ufw", "allow", "22689/tcp", "comment", "QCP-panel")
		return err
	case "firewalld":
		if !commandOK("firewall-cmd", "--state") {
			return errors.New("firewalld recorded for QCP but is not running")
		}
		if !commandOK("firewall-cmd", "--permanent", "--zone="+state.Zone, "--query-port=22689/tcp") {
			if _, err := commandOutput("firewall-cmd", "--permanent", "--zone="+state.Zone, "--add-port=22689/tcp"); err != nil {
				return err
			}
		}
		if !commandOK("firewall-cmd", "--zone="+state.Zone, "--query-port=22689/tcp") {
			_, err := commandOutput("firewall-cmd", "--zone="+state.Zone, "--add-port=22689/tcp")
			return err
		}
		return nil
	case "iptables":
		args := []string{"INPUT", "-p", "tcp", "--dport", "22689", "-m", "comment", "--comment", "QCP-panel", "-j", "ACCEPT"}
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
	for _, line := range strings.Split(status, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.EqualFold(fields[0], "22689/tcp") && strings.EqualFold(fields[1], "ALLOW") {
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
	switch state.Backend {
	case "ufw":
		_, err := commandOutput("ufw", "delete", "allow", "22689/tcp", "comment", "QCP-panel")
		return err
	case "firewalld":
		_, runtimeErr := commandOutput("firewall-cmd", "--zone="+state.Zone, "--remove-port=22689/tcp")
		_, permanentErr := commandOutput("firewall-cmd", "--permanent", "--zone="+state.Zone, "--remove-port=22689/tcp")
		if runtimeErr != nil {
			return runtimeErr
		}
		return permanentErr
	case "iptables":
		args := []string{"INPUT", "-p", "tcp", "--dport", "22689", "-m", "comment", "--comment", "QCP-panel", "-j", "ACCEPT"}
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
