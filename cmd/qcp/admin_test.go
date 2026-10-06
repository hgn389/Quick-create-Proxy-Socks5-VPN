package main

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestValidateNewAdminPassword(t *testing.T) {
	for _, password := range []string{"short", defaultAdminPassword, string(make([]byte, 73))} {
		if err := validateNewAdminPassword(password); err == nil {
			t.Errorf("accepted unsafe password %q", password)
		}
	}
	if err := validateNewAdminPassword("new-password-123"); err != nil {
		t.Fatalf("rejected valid password: %v", err)
	}
}

func TestValidAdminLoginRequiresUsernameAndPassword(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if !validAdminLogin(hash, "admin", "correct-password") {
		t.Fatal("valid admin credentials were rejected")
	}
	for _, input := range []struct {
		username string
		password string
	}{
		{username: "root", password: "correct-password"},
		{username: "admin", password: "wrong-password"},
	} {
		if validAdminLogin(hash, input.username, input.password) {
			t.Fatalf("invalid credentials accepted for username %q", input.username)
		}
	}
}
