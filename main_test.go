package main

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestParsePeers(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantLen  int
		wantKeys []string
	}{
		{"empty", "", 0, nil},
		{"single IP", "10.0.0.1", 1, []string{"10.0.0.1"}},
		{"multiple IPs", "10.0.0.1, 10.0.0.2, 10.0.0.3", 3, []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}},
		{"with CIDR", "10.0.0.0/24", 1, []string{"10.0.0.0/24"}},
		{"mixed", "10.0.0.1, 192.168.1.0/24", 2, []string{"10.0.0.1", "192.168.1.0/24"}},
		{"whitespace", "  10.0.0.1 , 10.0.0.2  ", 2, []string{"10.0.0.1", "10.0.0.2"}},
		{"invalid skipped", "10.0.0.1, not-an-ip, 10.0.0.2", 2, []string{"10.0.0.1", "10.0.0.2"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parsePeers(tt.input)
			if len(got) != tt.wantLen {
				t.Errorf("parsePeers(%q) returned %d entries, want %d", tt.input, len(got), tt.wantLen)
			}
			for _, k := range tt.wantKeys {
				if !got[k] {
					t.Errorf("parsePeers(%q) missing key %q", tt.input, k)
				}
			}
		})
	}
}

func TestIsClusterPeer(t *testing.T) {
	cfg := &Config{
		ClusterPeers: map[string]bool{
			"10.0.0.1":      true,
			"10.0.0.2":      true,
			"192.168.1.0/24": true,
		},
	}

	tests := []struct {
		addr string
		want bool
	}{
		{"10.0.0.1:12345", true},
		{"10.0.0.2:54321", true},
		{"10.0.0.3:12345", false},
		{"192.168.1.50:12345", true},
		{"192.168.1.255:12345", true},
		{"192.168.2.1:12345", false},
		{"8.8.8.8:53", false},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			got := isClusterPeer(cfg, tt.addr)
			if got != tt.want {
				t.Errorf("isClusterPeer(%q) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

func TestIsZoneTransferOrNotify(t *testing.T) {
	tests := []struct {
		name string
		msg  *dns.Msg
		want bool
	}{
		{
			"normal A query",
			&dns.Msg{Question: []dns.Question{{Name: "example.com.", Qtype: dns.TypeA}}},
			false,
		},
		{
			"AXFR",
			&dns.Msg{Question: []dns.Question{{Name: "example.com.", Qtype: dns.TypeAXFR}}},
			true,
		},
		{
			"IXFR",
			&dns.Msg{Question: []dns.Question{{Name: "example.com.", Qtype: dns.TypeIXFR}}},
			true,
		},
		{
			"NOTIFY",
			&dns.Msg{MsgHdr: dns.MsgHdr{Opcode: dns.OpcodeNotify}},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isZoneTransferOrNotify(tt.msg)
			if got != tt.want {
				t.Errorf("isZoneTransferOrNotify(%s) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"debug", "DEBUG"},
		{"info", "INFO"},
		{"warn", "WARN"},
		{"warning", "WARN"},
		{"error", "ERROR"},
		{"INFO", "INFO"},
		{"unknown", "INFO"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseLogLevel(tt.input)
			if got.String() != tt.want {
				t.Errorf("parseLogLevel(%q) = %s, want %s", tt.input, got.String(), tt.want)
			}
		})
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input    string
		fallback time.Duration
		want     time.Duration
	}{
		{"5s", time.Second, 5 * time.Second},
		{"100ms", time.Second, 100 * time.Millisecond},
		{"invalid", 3 * time.Second, 3 * time.Second},
		{"", 5 * time.Second, 5 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseDuration(tt.input, tt.fallback)
			if got != tt.want {
				t.Errorf("parseDuration(%q, %v) = %v, want %v", tt.input, tt.fallback, got, tt.want)
			}
		})
	}
}

// Integration test: spins up a mock upstream and the proxy, sends queries
func TestProxyIntegration(t *testing.T) {
	// Start a mock upstream DNS server
	upstreamAddr := startMockUpstream(t)

	cfg := &Config{
		ListenAddr:   "127.0.0.1:0", // OS picks a port
		Upstream:     upstreamAddr,
		ClusterPeers: map[string]bool{"127.0.0.1": true},
		Timeout:      2 * time.Second,
	}

	h := makeHandler(cfg)

	// Start proxy on a random port
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyAddr := pc.LocalAddr().String()
	srv := &dns.Server{PacketConn: pc, Handler: h}
	go srv.ActivateAndServe()
	defer srv.Shutdown()

	c := new(dns.Client)
	c.Timeout = 2 * time.Second

	// Test 1: Query for authoritative zone → should get answer
	m := new(dns.Msg)
	m.SetQuestion("auth.example.com.", dns.TypeA)
	resp, _, err := c.Exchange(m, proxyAddr)
	if err != nil {
		t.Fatalf("authoritative query failed: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("authoritative query: got rcode %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if !resp.Authoritative {
		t.Error("authoritative query: expected AA flag set")
	}

	// Test 2: Query for non-authoritative zone → should get REFUSED
	// (from 127.0.0.1 which is a cluster peer, so it'll be bypassed)
	// We need to test from a non-peer perspective... but since we're
	// on localhost and 127.0.0.1 is in peers, let's remove it.
	cfg.ClusterPeers = map[string]bool{} // clear peers

	m2 := new(dns.Msg)
	m2.SetQuestion("recursive.example.com.", dns.TypeA)
	resp2, _, err := c.Exchange(m2, proxyAddr)
	if err != nil {
		t.Fatalf("non-authoritative query failed: %v", err)
	}
	if resp2.Rcode != dns.RcodeRefused {
		t.Errorf("non-authoritative query: got rcode %s, want REFUSED", dns.RcodeToString[resp2.Rcode])
	}

	// Test 3: Same non-auth query but as a cluster peer → should pass through
	cfg.ClusterPeers = map[string]bool{"127.0.0.1": true}
	m3 := new(dns.Msg)
	m3.SetQuestion("recursive.example.com.", dns.TypeA)
	resp3, _, err := c.Exchange(m3, proxyAddr)
	if err != nil {
		t.Fatalf("peer query failed: %v", err)
	}
	if resp3.Rcode != dns.RcodeSuccess {
		t.Errorf("peer query: got rcode %s, want NOERROR", dns.RcodeToString[resp3.Rcode])
	}
}

// startMockUpstream creates a DNS server that returns AA for "auth.example.com"
// and non-AA for everything else.
func startMockUpstream(t *testing.T) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)

		if len(r.Question) > 0 && r.Question[0].Name == "auth.example.com." {
			// Authoritative response
			m.Authoritative = true
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			})
		} else {
			// Non-authoritative (recursive) response
			m.Authoritative = false
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("8.8.8.8"),
			})
		}

		w.WriteMsg(m)
	})

	srv := &dns.Server{PacketConn: pc, Handler: handler}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })

	return pc.LocalAddr().String()
}
