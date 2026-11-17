package egress

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
)

func TestIsBlockedIP(t *testing.T) {
	tests := []struct {
		address string
		blocked bool
	}{
		{address: "127.0.0.1", blocked: true},
		{address: "::1", blocked: true},
		{address: "10.1.2.3", blocked: true},
		{address: "169.254.169.254", blocked: true},
		{address: "::ffff:192.168.1.2", blocked: true},
		{address: "100.64.0.1", blocked: true},
		{address: "224.0.0.1", blocked: true},
		{address: "93.184.216.34", blocked: false},
	}

	for _, test := range tests {
		t.Run(test.address, func(t *testing.T) {
			ip := netip.MustParseAddr(test.address)
			if got := isBlockedIP(ip); got != test.blocked {
				t.Fatalf("isBlockedIP(%q) = %t, want %t", test.address, got, test.blocked)
			}
		})
	}
}

func TestOutboundClientBlocksLoopbackAndRedirects(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()

	client := NewHTTPClient()
	if _, err := client.Get(server.URL); err == nil {
		t.Fatal("expected loopback request to be rejected")
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("loopback server received %d requests", got)
	}

	if client.CheckRedirect == nil {
		t.Fatal("redirects are not disabled")
	}
	err := client.CheckRedirect(&http.Request{}, []*http.Request{{}})
	if !errors.Is(err, ErrRedirect) {
		t.Fatalf("CheckRedirect() = %v, want ErrRedirect", err)
	}
}
