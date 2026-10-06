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
