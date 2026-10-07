package certificates

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"github.com/fly12323/RWAF/internal/config"
)

func TestPrivateKeyEncryptionRoundTripAndTamperRejection(t *testing.T) {
	previous := config.GlobalConfig
	defer func() { config.GlobalConfig = previous }()
	path := filepath.Join(t.TempDir(), "keys", "master.key")
	config.GlobalConfig = &config.Config{Proxy: config.ProxyConfig{TLSKeyFile: path}}
	plain := "-----BEGIN PRIVATE KEY-----\nprivate-content\n-----END PRIVATE KEY-----"
	first, err := Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	if first == second || strings.Contains(first, "private-content") {
		t.Fatal("encryption did not use random nonce")
	}
	value, err := Decrypt(first)
	if err != nil || value != plain {
		t.Fatal("key round trip failed", err)
	}
	key, err := os.ReadFile(path)
	if err != nil || len(key) != 32 {
		t.Fatal("master key", err)
	}
	if err := os.WriteFile(path, make([]byte, 32), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(first); err == nil {
		t.Fatal("wrong master key accepted")
	}
	for _, invalid := range []string{"", plain, "v1:AA==", "v1:???"} {
		if _, err := Decrypt(invalid); err == nil {
			t.Fatal("invalid encrypted key accepted")
		}
	}
}
