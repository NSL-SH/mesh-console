// Package routing infers how public traffic reaches this box from the routes
// the backend holds for it.
//
// The gateways pick deterministically and without failover — routes are
// validated at registration, not at request time (mesh-router-gateway
// nginx/lua/resolver.lua): keep the routes matching the request scheme (all of
// them if none match), sort by priority ascending with a missing priority as
// 999, take the first.
//
// So "current" is an inference from the registry, not an observation of live
// traffic, and the UI says so.
package routing

import (
	"sort"

	"github.com/nsl-sh/mesh-console/internal/backend"
)

type Mode string

const (
	ModeDirect  Mode = "direct"  // an agent route wins
	ModeTunnel  Mode = "tunnel"  // a tunnel route wins
	ModeOther   Mode = "other"   // a route from an unknown source wins
	ModeOffline Mode = "offline" // nothing registered, or it has expired
)

type Pick struct {
	Mode  Mode           `json:"mode"`
	Route *backend.Route `json:"route,omitempty"`
}

type State struct {
	// Mode is the headline: what the gateway would do for an https request.
	Mode Mode `json:"mode"`
	// Gateway is the gateway's pick, with the route it would use.
	Gateway Pick `json:"gateway"`
	// HasAgent / HasTunnel say whether each path is registered at all, so the UI
	// can tell "tunnel because direct failed" from "tunnel only".
	HasAgent  bool `json:"hasAgent"`
	HasTunnel bool `json:"hasTunnel"`
}

const missingPriority = 999

// Infer computes the state for an https request, which is what browsers send.
// ttl is the backend's routesTtl; <= 0 with no routes means nothing is live
// (-2 is Redis for "no key").
func Infer(routes []backend.Route, ttl int) State {
	s := State{Mode: ModeOffline, Gateway: Pick{Mode: ModeOffline}}
	for _, r := range routes {
		switch r.Source {
		case "agent":
			s.HasAgent = true
		case "tunnel":
			s.HasTunnel = true
		}
	}
	if len(routes) == 0 && ttl <= 0 {
		return s
	}
	s.Gateway = pick(routes, "https")
	s.Mode = s.Gateway.Mode
	return s
}

func pick(routes []backend.Route, scheme string) Pick {
	var matching []backend.Route
	for _, r := range routes {
		if schemeOf(r) == scheme {
			matching = append(matching, r)
		}
	}
	if len(matching) == 0 {
		matching = routes
	}
	if len(matching) == 0 {
		return Pick{Mode: ModeOffline}
	}
	matching = append([]backend.Route(nil), matching...)
	sort.SliceStable(matching, func(i, j int) bool { return prio(matching[i]) < prio(matching[j]) })
	best := matching[0]
	return Pick{Mode: modeOf(best), Route: &best}
}

func schemeOf(r backend.Route) string {
	if r.Scheme == "" {
		return "https" // backend default
	}
	return r.Scheme
}

func prio(r backend.Route) int {
	if r.Priority == 0 {
		return missingPriority
	}
	return r.Priority
}

func modeOf(r backend.Route) Mode {
	switch r.Source {
	case "agent":
		return ModeDirect
	case "tunnel":
		return ModeTunnel
	default:
		return ModeOther
	}
}
