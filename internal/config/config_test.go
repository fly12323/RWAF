package config

import (
	"net/url"
	"testing"
)

func TestPostgresDSNEscapesCredentialsAndIPv6(t *testing.T) {
	cfg := DatabaseConfig{Host: "::1", Port: 5432, Username: "user@name", Password: "space :/@?&", Database: "waf", SSLMode: "require"}
	u, err := url.Parse(cfg.DSN())
	if err != nil {
		t.Fatal(err)
	}
	password, _ := u.User.Password()
	if u.User.Username() != cfg.Username || password != cfg.Password || u.Host != "[::1]:5432" || u.Query().Get("timezone") != "Asia/Shanghai" || u.Query().Get("sslmode") != "require" {
		t.Fatal("DSN fields did not round-trip")
	}
}
