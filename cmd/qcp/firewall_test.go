package main

import "testing"

func TestUFWAllowsPanel(t *testing.T) {
	for _, status := range []string{
		"Status: active\n\n22689/tcp                 ALLOW       Anywhere",
		"Status: active\n22689/tcp                 ALLOW IN    203.0.113.4",
	} {
		if !ufwAllowsPanel(status) {
			t.Fatalf("allow rule was not recognized: %q", status)
		}
	}
	for _, status := range []string{
		"Status: inactive",
		"Status: active\n22689/tcp                 DENY        Anywhere",
		"Status: active\n122689/tcp                ALLOW       Anywhere",
	} {
		if ufwAllowsPanel(status) {
			t.Fatalf("non-allow rule was accepted: %q", status)
		}
	}
}

func TestUFWAllowsTCPPort(t *testing.T) {
	status := "Status: active\n10037/tcp                 ALLOW       Anywhere\n10037/tcp (v6)            ALLOW       Anywhere (v6)"
	if !ufwAllowsTCPPort(status, 10037) {
		t.Fatal("custom proxy port allow rule was not recognized")
	}
	if ufwAllowsTCPPort(status, 10038) {
		t.Fatal("different proxy port was incorrectly accepted")
	}
}
