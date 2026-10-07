package password

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

var Defaults = []string{"123456", "12345678", "123456789", "1234567890", "123123", "12345", "1234", "password", "Password123", "password123", "admin", "admin123", "admin@123", "qwerty", "qwerty123", "abc123", "abcdef", "abcdefgh", "111111", "11111111", "000000", "00000000", "888888", "666666", "123456a", "a123456", "welcome", "welcome123", "letmein", "changeme", "root", "root123", "test", "test123", "guest", "guest123", "passw0rd", "P@ssw0rd", "P@ssw0rd123", "Password123!"}
var Formats = []string{"plain", "md5", "sha1", "sha256", "base64", "base64url"}

type PolicyError struct{ Message string }

func (e *PolicyError) Error() string { return e.Message }

func Encode(s, format string) string {
	switch format {
	case "plain":
		return s
	case "md5":
		h := md5.Sum([]byte(s))
		return hex.EncodeToString(h[:])
	case "sha1":
		h := sha1.Sum([]byte(s))
		return hex.EncodeToString(h[:])
	case "sha256":
		h := sha256.Sum256([]byte(s))
		return hex.EncodeToString(h[:])
	case "base64":
		return base64.StdEncoding.EncodeToString([]byte(s))
	case "base64url":
		return base64.RawURLEncoding.EncodeToString([]byte(s))
	}
	return ""
}

// ValidateAdmin enforces a stable policy independent of editable traffic dictionaries.
func ValidateAdmin(s, username string) (err error) {
	defer func() {
		if err != nil {
			err = &PolicyError{Message: err.Error()}
		}
	}()
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) < 12 || len(s) > 72 {
		return fmt.Errorf("管理账号密码至少 12 个字符，且不超过 72 字节")
	}
	lower := strings.ToLower(s)
	if strings.TrimSpace(s) != s || strings.EqualFold(s, username) || (len(username) >= 3 && strings.HasPrefix(lower, strings.ToLower(username))) {
		return fmt.Errorf("密码不能以账号名开头或包含首尾空白")
	}
	for _, word := range Defaults {
		if strings.EqualFold(word, s) {
			return fmt.Errorf("不能使用常见弱口令")
		}
	}
	for _, base := range []string{"password", "admin", "welcome", "qwerty", "letmein", "changeme", "test", "root"} {
		if strings.HasPrefix(lower, base) {
			suffix := strings.TrimPrefix(lower, base)
			letters := false
			for _, r := range suffix {
				if unicode.IsLetter(r) {
					letters = true
				}
			}
			if !letters {
				return fmt.Errorf("不能使用常见口令加数字或符号的简单组合")
			}
		}
	}
	runes := []rune(s)
	numeric := true
	for _, r := range runes {
		if !unicode.IsDigit(r) {
			numeric = false
		}
	}
	if numeric {
		return fmt.Errorf("不能使用纯数字密码")
	}
	for period := 1; period <= len(runes)/2; period++ {
		if len(runes)%period != 0 {
			continue
		}
		repeats := true
		for i := period; i < len(runes); i++ {
			if runes[i] != runes[i%period] {
				repeats = false
				break
			}
		}
		if repeats {
			return fmt.Errorf("不能使用重复字符组合")
		}
	}
	if strings.Contains("abcdefghijklmnopqrstuvwxyz", lower) || strings.Contains("qwertyuiopasdfghjklzxcvbnm", lower) {
		return fmt.Errorf("不能使用重复或连续字符密码")
	}
	return nil
}
