package postgres

import "testing"

func TestValidateLocalHost(t *testing.T) {
	for _, host := range []string{"localhost", "127.0.0.1", "::1", "/tmp"} {
		if err := validateLocalHost(host); err != nil {
			t.Errorf("validateLocalHost(%q): %v", host, err)
		}
	}
	for _, host := range []string{"db.example.com", "192.168.1.10"} {
		if err := validateLocalHost(host); err == nil {
			t.Errorf("validateLocalHost(%q) unexpectedly succeeded", host)
		}
	}
}
