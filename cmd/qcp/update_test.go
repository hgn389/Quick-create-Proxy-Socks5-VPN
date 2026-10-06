package main

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{{"v1.0.0-beta.2", "v1.0.0-beta.1", 1}, {"v1.0.0-beta.10", "v1.0.0-beta.2", 1}, {"v1.0.0", "v1.0.0-beta.9", 1}, {"v1.1.0", "v1.0.9", 1}, {"v1.0.0-beta.1", "v1.0.0", -1}, {"v1.0.0", "v1.0.0", 0}}
	for _, tc := range cases {
		got, err := compareVersions(tc.a, tc.b)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Errorf("compare %s %s = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
	for _, bad := range []string{"v1.0", "v01.0.0", "v1.0.0-beta.01", "garbage"} {
		if _, _, ok := versionParts(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
}
func TestAssetForRelease(t *testing.T) {
	tag := "v1.0.1"
	name := expectedReleaseAsset(tag)
	r := githubRelease{TagName: tag, Assets: []githubAsset{{Name: name, Digest: "sha256:" + strings.Repeat("a", 64), Size: 123, State: "uploaded"}}}
	if _, ok := assetForRelease(r); !ok {
		t.Fatal("valid asset was rejected")
	}
	r.Assets[0].Digest = ""
	if _, ok := assetForRelease(r); ok {
		t.Fatal("asset without SHA256 was accepted")
	}
}
func TestExtractRelease(t *testing.T) {
	tag := "v1.0.1"
	for _, tc := range []struct {
		extra string
		valid bool
	}{{"", true}, {"qcp-v1.0.1/../escape", false}, {"other/install.sh", false}} {
		dir := t.TempDir()
		archive := filepath.Join(dir, "bundle.tar.gz")
		file, err := os.Create(archive)
		if err != nil {
			t.Fatal(err)
		}
		gz := gzip.NewWriter(file)
		tw := tar.NewWriter(gz)
		write := func(name, content string) {
			t.Helper()
			data := []byte(content)
			if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write(data); err != nil {
				t.Fatal(err)
			}
		}
		write("qcp-v1.0.1/VERSION", "1.0.1")
		write("qcp-v1.0.1/install.sh", "#!/bin/sh\n")
		write("qcp-v1.0.1/dist/go/SHA256SUMS", "placeholder")
		write("qcp-v1.0.1/dist/vendor/3proxy/SHA256SUMS", "placeholder")
		if tc.extra != "" {
			write(tc.extra, "bad")
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		root, err := extractRelease(archive, filepath.Join(dir, "stage"), tag)
		if tc.valid {
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(root, "VERSION"))
			if err != nil || string(data) != "1.0.1" {
				t.Fatalf("invalid version file: %v", err)
			}
		} else if err == nil {
			t.Fatalf("unsafe path %q was accepted", tc.extra)
		}
		if !tc.valid && strings.Contains(tc.extra, "escape") {
			if _, e := os.Stat(filepath.Join(dir, "escape")); e == nil {
				t.Fatal("archive escaped staging directory")
			}
		}
	}
}

func TestExtractPackagedRelease(t *testing.T) {
	archive := filepath.Join("..", "..", "dist", "release", "qcp-v"+version+"-linux-amd64-arm64.tar.gz")
	if _, err := os.Stat(archive); os.IsNotExist(err) {
		t.Skip("release archive has not been built")
	}
	root, err := extractRelease(archive, t.TempDir(), "v"+version)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "dist", "go", "qcp-linux-arm64")); err != nil {
		t.Fatal(err)
	}
}
