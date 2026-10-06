package proxycfg

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"golang.org/x/crypto/blake2b"
)

type Spec struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Port       int    `json:"port"`
	Username   string `json:"username"`
	SourceCIDR string `json:"source_cidr"`
	PasswordCR string `json:"password_cr"`
	Enabled    bool   `json:"enabled"`
	CreatedAt  string `json:"created_at"`
}

var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$`)
var safeUser = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$`)
var safeID = regexp.MustCompile(`^[a-f0-9]{16}$`)

func Validate(s Spec) error {
	if !safeID.MatchString(s.ID) {
		return errors.New("invalid proxy ID")
	}
	if !safeName.MatchString(s.Name) {
		return errors.New("name must be 1-64 plain characters")
	}
	if s.Kind != "socks5" && s.Kind != "http" {
		return errors.New("proxy kind must be socks5 or http")
	}
	if s.Port < 10000 || s.Port > 19999 {
		return errors.New("port must be in 10000-19999")
	}
	if !safeUser.MatchString(s.Username) {
		return errors.New("username must be 1-32 plain characters")
	}
	if s.SourceCIDR != "" {
		p, err := netip.ParsePrefix(s.SourceCIDR)
		if err != nil || !p.Addr().Is4() || p.Addr().Zone() != "" {
			return errors.New("source must be an IPv4 CIDR")
		}
	}
	if !strings.HasPrefix(s.PasswordCR, "$3$") || strings.ContainsAny(s.PasswordCR, "\r\n\"\\") {
		return errors.New("invalid proxy password hash")
	}
	return nil
}

func NewPassword() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func NewID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

// HashPassword produces the $3$ BLAKE2b-crypt format used by 3proxy 0.9.9.x.
// Upstream hashes password including its terminating NUL, then salt, to a
// 16-byte BLAKE2b digest and uses its crypt64 byte permutation.
func HashPassword(password string) (string, error) {
	if len(password) < 20 || len(password) > 128 || strings.ContainsRune(password, 0) {
		return "", errors.New("proxy password must contain 20-128 bytes and no NUL")
	}
	saltBytes := make([]byte, 12)
	if _, err := rand.Read(saltBytes); err != nil {
		return "", err
	}
	salt := base64.RawURLEncoding.EncodeToString(saltBytes)
	return hashPasswordWithSalt(password, salt)
}

func hashPasswordWithSalt(password, salt string) (string, error) {
	if len(password) < 20 || len(password) > 128 || strings.ContainsRune(password, 0) {
		return "", errors.New("proxy password must contain 20-128 bytes and no NUL")
	}
	if len(salt) == 0 || len(salt) > 64 || strings.ContainsAny(salt, "$\r\n\"\\") {
		return "", errors.New("invalid salt")
	}
	digest, err := blake2b.New(16, nil)
	if err != nil {
		return "", err
	}
	_, _ = digest.Write([]byte(password))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(salt))
	b := digest.Sum(nil)
	var encoded strings.Builder
	encoded.Grow(22)
	for _, triple := range [][3]int{{0, 6, 12}, {1, 7, 13}, {2, 8, 14}, {3, 9, 15}, {4, 10, 5}} {
		v := uint32(b[triple[0]])<<16 | uint32(b[triple[1]])<<8 | uint32(b[triple[2]])
		crypt64(&encoded, v, 4)
	}
	crypt64(&encoded, uint32(b[11]), 2)
	return "$3$" + salt + "$" + encoded.String(), nil
}

func crypt64(out *strings.Builder, value uint32, n int) {
	const alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	for range n {
		out.WriteByte(alphabet[value&0x3f])
		value >>= 6
	}
}

func Render(s Spec) (string, error) {
	if err := Validate(s); err != nil {
		return "", err
	}
	source := s.SourceCIDR
	listenIP := "0.0.0.0"
	if source == "" {
		source = "127.0.0.1/32"
		listenIP = "127.0.0.1"
	}
	operation := "CONNECT"
	service := "socks"
	options := " -4 -u2"
	if s.Kind == "http" {
		operation = "HTTP,HTTP_CONNECT"
		service = "proxy"
		options = " -4"
	}
	// Each service has its own process and ACL. The denied destinations cover
	// loopback, private, link-local, CGNAT, multicast and reserved IPv4 ranges.
	return fmt.Sprintf(`# Managed by qcp. Manual changes are overwritten.
log
maxconn 200
auth strong
users "%s:CR:%s"
deny * * 0.0.0.0/8
deny * * 10.0.0.0/8
deny * * 100.64.0.0/10
deny * * 127.0.0.0/8
deny * * 169.254.0.0/16
deny * * 172.16.0.0/12
deny * * 192.168.0.0/16
deny * * 198.18.0.0/15
deny * * 224.0.0.0/4
deny * * 240.0.0.0/4
allow %s %s * * %s
deny *
%s -p%d -i%s%s
`, s.Username, s.PasswordCR, s.Username, source, operation, service, s.Port, listenIP, options), nil
}
