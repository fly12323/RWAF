package password

import "testing"

func TestAdminPolicy(t *testing.T) {
	for _, p := range []string{"admin123", "123456789012", "Password12345!", "qwertyuiopasdf", "aaaaaaaaaaaa", "abcabcabcabc", "admin-longpassword", "short!", " passphrase with blanks "} {
		if ValidateAdmin(p, "admin") == nil {
			t.Fatalf("weak password accepted: %q", p)
		}
	}
	for _, p := range []string{"Bench-Setup!2026-Safe", "three unusual words together", "紫色的小船驶向遥远的岛屿"} {
		if err := ValidateAdmin(p, "admin"); err != nil {
			t.Fatalf("strong passphrase rejected: %v", err)
		}
	}
}
