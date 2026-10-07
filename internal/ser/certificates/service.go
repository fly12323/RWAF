package certificates

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"github.com/fly12323/RWAF/internal/config"
	"github.com/fly12323/RWAF/internal/model"
)

var keyMu sync.Mutex

func masterKey() ([]byte, error) {
	keyMu.Lock()
	defer keyMu.Unlock()
	path := config.GetConfig().Proxy.TLSKeyFile
	if path == "" {
		return nil, errors.New("TLS encryption key path is not configured")
	}
	key, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, err
		}
		key = make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return nil, err
		}
		// Exclusive creation prevents concurrent instances replacing the master key.
		f, createErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if createErr != nil {
			return nil, createErr
		}
		_, err = f.Write(key)
		if err == nil {
			err = f.Sync()
		}
		err = errors.Join(err, f.Close())
	}
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("TLS master key must contain 32 bytes")
	}
	return key, nil
}

func gcm() (cipher.AEAD, error) {
	key, err := masterKey()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func Encrypt(privateKey string) (string, error) {
	c, err := gcm()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, c.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := c.Seal(nonce, nonce, []byte(privateKey), []byte("waf-tls-key-v1"))
	return "v1:" + base64.StdEncoding.EncodeToString(sealed), nil
}

func Decrypt(encrypted string) (string, error) {
	if !strings.HasPrefix(encrypted, "v1:") {
		return "", errors.New("invalid encrypted TLS key")
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(encrypted, "v1:"))
	if err != nil {
		return "", err
	}
	c, err := gcm()
	if err != nil {
		return "", err
	}
	if len(data) < c.NonceSize() {
		return "", errors.New("invalid encrypted TLS key length")
	}
	value, err := c.Open(nil, data[:c.NonceSize()], data[c.NonceSize():], []byte("waf-tls-key-v1"))
	if err != nil {
		return "", errors.New("cannot decrypt TLS key; check master key backup")
	}
	return string(value), nil
}

func Validate(certPEM, keyPEM string, domains []string) (*tls.Certificate, error) {
	if len(certPEM) > 128*1024 || len(keyPEM) > 32*1024 {
		return nil, errors.New("证书或私钥超过大小上限")
	}
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, errors.New("证书与私钥格式错误或不匹配")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, errors.New("证书尚未生效或已经过期")
	}
	if len(domains) == 0 {
		return nil, errors.New("HTTPS 站点必须配置域名")
	}
	for _, domain := range domains {
		if err := leaf.VerifyHostname(domain); err != nil {
			return nil, fmt.Errorf("证书未覆盖域名 %s", domain)
		}
	}
	cert.Leaf = leaf
	return &cert, nil
}

func ForSite(site *model.Site, domains []string) (*tls.Certificate, error) {
	key, err := Decrypt(site.TLSPrivateKey)
	if err != nil {
		return nil, err
	}
	return Validate(site.TLSCertificate, key, domains)
}
