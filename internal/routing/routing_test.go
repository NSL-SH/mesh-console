package routing

import (
	"testing"

	"github.com/nsl-sh/mesh-console/internal/backend"
)

func agentDomain(scheme string) backend.Route {
	return backend.Route{IP: "203.0.113.5", Port: 443, Priority: 1, Source: "agent", Scheme: scheme, Type: "domain", Domain: "203-0-113-5.ip.nsl.sh"}
}

func tunnel(scheme string) backend.Route {
	return backend.Route{IP: "10.0.0.2", Port: 80, Priority: 2, Source: "tunnel", Scheme: scheme}
}

func TestInfer(t *testing.T) {
	cases := []struct {
		name          string
		routes        []backend.Route
		ttl           int
		mode, gw     Mode
	}{
		{"nothing registered", nil, -2, ModeOffline, ModeOffline},
		{"agent and tunnel", []backend.Route{tunnel("https"), tunnel("http"), agentDomain("https"), agentDomain("http")}, 500, ModeDirect, ModeDirect},
		{"tunnel only", []backend.Route{tunnel("https"), tunnel("http")}, 500, ModeTunnel, ModeTunnel},
		{"agent only", []backend.Route{agentDomain("https")}, 500, ModeDirect, ModeDirect},
		{
			"agent ip route wins over the tunnel",
			[]backend.Route{{IP: "203.0.113.5", Port: 443, Priority: 1, Source: "agent", Type: "ip"}, tunnel("https")},
			500, ModeDirect, ModeDirect,
		},
		{
			"agent demoted below the tunnel (forced tunnel): tunnel wins",
			[]backend.Route{tunnel("https"), func() backend.Route { r := agentDomain("https"); r.Priority = 3; return r }()},
			500, ModeTunnel, ModeTunnel,
		},
		{
			"a tie keeps the first registered route",
			[]backend.Route{tunnel("https"), func() backend.Route { r := agentDomain("https"); r.Priority = 2; return r }()},
			500, ModeTunnel, ModeTunnel,
		},
		{
			"missing priority sorts last",
			[]backend.Route{{Source: "agent", Scheme: "https", Type: "domain", Domain: "x.ip.nsl.sh"}, tunnel("https")},
			500, ModeTunnel, ModeTunnel,
		},
		{
			"no scheme match falls back to all routes",
			[]backend.Route{tunnel("http")},
			500, ModeTunnel, ModeTunnel,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := Infer(tc.routes, tc.ttl)
			if s.Mode != tc.mode || s.Gateway.Mode != tc.gw {
				t.Fatalf("got mode=%s gateway=%s, want %s/%s", s.Mode, s.Gateway.Mode, tc.mode, tc.gw)
			}
		})
	}
}

func TestInferFlags(t *testing.T) {
	s := Infer([]backend.Route{tunnel("https"), agentDomain("https")}, 100)
	if !s.HasAgent || !s.HasTunnel {
		t.Fatalf("flags = %+v", s)
	}
}
