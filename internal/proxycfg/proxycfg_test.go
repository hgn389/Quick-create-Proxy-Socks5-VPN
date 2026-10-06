package proxycfg

import (
	"strings"
	"testing"
)

func TestHashMatches3proxyCrypt(t *testing.T) {
	// Independent vector from upstream 3proxy_crypt 0.9.9.0.
	got, err := hashPasswordWithSalt("QcpDummyPassword1234567890", "QcpTestSalt")
	if err != nil {
		t.Fatal(err)
	}
	const want = "$3$QcpTestSalt$iKDtddjTgDGA4.Do0DZ3//"
	if got != want {
		t.Fatalf("3proxy hash mismatch: got %q", got)
	}
}

func TestRenderDefaultsToLoopbackAndRequiresAuth(t *testing.T) {
	hash, err := hashPasswordWithSalt("QcpDummyPassword1234567890", "QcpTestSalt")
	if err != nil {
		t.Fatal(err)
	}
	config, err := Render(Spec{ID: "0123456789abcdef", Name: "example", Kind: "socks5", Port: 10421, Username: "user01", PasswordCR: hash})
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"auth strong", "-i127.0.0.1", " -4 -u2", "127.0.0.1/32", "allow user01", "CONNECT", "deny * * 169.254.0.0/16"} {
		if !strings.Contains(config, fragment) {
			t.Errorf("generated config is missing %q", fragment)
		}
	}
}

func TestRenderRejectsConfigInjection(t *testing.T) {
	hash, err := hashPasswordWithSalt("QcpDummyPassword1234567890", "QcpTestSalt")
	if err != nil {
		t.Fatal(err)
	}
	_, err = Render(Spec{ID: "0123456789abcdef", Name: "x\nproxy -p80", Kind: "socks5", Port: 10421, Username: "user01", PasswordCR: hash})
	if err == nil {
		t.Fatal("configuration injection was accepted")
	}
}
