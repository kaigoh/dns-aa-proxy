package main

import (
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type Config struct {
	ListenAddr   string
	Upstream     string
	ClusterPeers map[string]bool
	Timeout      time.Duration
	LogLevel     slog.Level
}

func loadConfig() Config {
	cfg := Config{
		ListenAddr:   envOr("LISTEN_ADDR", ":53"),
		Upstream:     envOr("UPSTREAM", "127.0.0.1:5353"),
		ClusterPeers: parsePeers(os.Getenv("CLUSTER_PEERS")),
		Timeout:      parseDuration(envOr("UPSTREAM_TIMEOUT", "5s"), 5*time.Second),
		LogLevel:     parseLogLevel(envOr("LOG_LEVEL", "info")),
	}
	return cfg
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func parsePeers(raw string) map[string]bool {
	peers := make(map[string]bool)
	if raw == "" {
		return peers
	}
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			// Resolve CIDR or plain IP
			if strings.Contains(p, "/") {
				// Store as CIDR string for later matching
				_, _, err := net.ParseCIDR(p)
				if err != nil {
					slog.Warn("invalid CIDR in CLUSTER_PEERS, skipping", "value", p, "error", err)
					continue
				}
				peers[p] = true
			} else {
				ip := net.ParseIP(p)
				if ip == nil {
					slog.Warn("invalid IP in CLUSTER_PEERS, skipping", "value", p)
					continue
				}
				peers[ip.String()] = true
			}
		}
	}
	return peers
}

func parseDuration(raw string, fallback time.Duration) time.Duration {
	d, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return d
}

func parseLogLevel(raw string) slog.Level {
	switch strings.ToLower(raw) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func isClusterPeer(cfg *Config, addr string, mu *sync.Mutex) bool {
	mu.Lock()
	defer mu.Unlock()

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	// Check direct IP match
	if cfg.ClusterPeers[ip.String()] {
		return true
	}

	// Check CIDR matches
	for peer := range cfg.ClusterPeers {
		if strings.Contains(peer, "/") {
			_, cidr, err := net.ParseCIDR(peer)
			if err != nil {
				continue
			}
			if cidr.Contains(ip) {
				return true
			}
		}
	}

	return false
}

// isZoneTransferOrNotify returns true for opcodes/qtypes that are part of
// cluster synchronisation and should always be forwarded transparently.
func isZoneTransferOrNotify(r *dns.Msg) bool {
	if r.Opcode == dns.OpcodeNotify {
		return true
	}
	for _, q := range r.Question {
		if q.Qtype == dns.TypeAXFR || q.Qtype == dns.TypeIXFR {
			return true
		}
	}
	return false
}

func makeHandler(cfg *Config, mu *sync.Mutex) dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		clientAddr := w.RemoteAddr().String()
		host, _, _ := net.SplitHostPort(clientAddr)

		qname := ""
		qtype := ""
		if len(r.Question) > 0 {
			qname = r.Question[0].Name
			qtype = dns.TypeToString[r.Question[0].Qtype]
		}

		logger := slog.With("client", host, "qname", qname, "qtype", qtype)

		peer := isClusterPeer(cfg, clientAddr, mu)
		clusterOp := isZoneTransferOrNotify(r)

		// Cluster peers and zone-transfer/NOTIFY ops are always passed through
		bypass := peer || clusterOp

		if bypass {
			logger.Debug("bypassing AA check", "peer", peer, "cluster_op", clusterOp)
		}

		// Forward to upstream, preserving protocol
		c := new(dns.Client)
		network := w.RemoteAddr().Network()
		c.Net = network
		c.Timeout = cfg.Timeout

		// AXFR/IXFR requires TCP
		if clusterOp && network == "udp" {
			c.Net = "tcp"
		}

		resp, rtt, err := c.Exchange(r, cfg.Upstream)
		if err != nil {
			logger.Error("upstream exchange failed", "error", err)
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeServerFailure)
			w.WriteMsg(m)
			return
		}

		logger.Debug("upstream response", "rtt", rtt, "rcode", dns.RcodeToString[resp.Rcode], "aa", resp.Authoritative)

		if bypass || resp.Authoritative {
			if resp.Authoritative {
				logger.Debug("forwarding authoritative response")
			}
			w.WriteMsg(resp)
			return
		}

		// Non-authoritative response from a non-peer client → REFUSED
		logger.Info("refused non-authoritative query")
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(m)
	}
}

func main() {
	cfg := loadConfig()

	mu := sync.Mutex{}

	// Configure structured logging
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel})
	slog.SetDefault(slog.New(handler))

	slog.Info("starting dns-aa-proxy",
		"listen", cfg.ListenAddr,
		"upstream", cfg.Upstream,
		"cluster_peers", len(cfg.ClusterPeers),
		"timeout", cfg.Timeout.String(),
	)

	for peer := range cfg.ClusterPeers {
		slog.Info("cluster peer registered", "peer", peer)
	}

	h := makeHandler(&cfg, &mu)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		srv := &dns.Server{Addr: cfg.ListenAddr, Net: "udp", Handler: h}
		slog.Info("listening", "protocol", "udp", "addr", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil {
			slog.Error("udp server failed", "error", err)
			os.Exit(1)
		}
	}()

	go func() {
		defer wg.Done()
		srv := &dns.Server{Addr: cfg.ListenAddr, Net: "tcp", Handler: h}
		slog.Info("listening", "protocol", "tcp", "addr", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil {
			slog.Error("tcp server failed", "error", err)
			os.Exit(1)
		}
	}()

	wg.Wait()
}
