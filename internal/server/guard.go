package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/nsl-sh/mesh-console/internal/hostverb"
)

// ---- guard (IP bans) -------------------------------------------------------
//
// The guard stack's bans as the template reports them (tools/guard.sh,
// hostverb.GuardTool): this box's own bans, the fleet list it imports, the
// allowlists, and the owner's actions on them. Every read and write is a verb: the
// console never talks to CrowdSec itself.

// guardUnavailable answers when the template has no guard tool; true when it did.
func (s *Server) guardUnavailable(w http.ResponseWriter) bool {
	if s.templateHasTool(hostverb.GuardTool) {
		return false
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"available": false,
		"blocked":   "this box's template does not ship " + hostverb.GuardTool + " yet - it arrives with a template update",
	})
	return true
}

// guardStatus runs `guard.sh status` and returns its JSON line, or writes the error.
func (s *Server) guardStatus(w http.ResponseWriter, r *http.Request) (json.RawMessage, bool) {
	verb, err := hostverb.GuardStatus(s.cfg.Scripts())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return nil, false
	}
	res, err := s.runVerb(r.Context(), verb)
	if err != nil {
		s.verbError(w, err)
		return nil, false
	}
	status := lastJSONLine(res.Output)
	if res.ExitCode != 0 || status == nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "could not read the guard's state", "result": res})
		return nil, false
	}
	return status, true
}

func (s *Server) handleGuard(w http.ResponseWriter, r *http.Request) {
	if s.guardUnavailable(w) {
		return
	}
	if status, ok := s.guardStatus(w, r); ok {
		writeJSON(w, http.StatusOK, map[string]any{"available": true, "status": status})
	}
}

func (s *Server) handleGuardLookup(w http.ResponseWriter, r *http.Request) {
	if s.guardUnavailable(w) {
		return
	}
	verb, err := hostverb.GuardLookup(s.cfg.Scripts(), r.URL.Query().Get("ip"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := s.runVerb(r.Context(), verb)
	if err != nil {
		s.verbError(w, err)
		return
	}
	switch res.ExitCode {
	case 0:
		if found := lastJSONLine(res.Output); found != nil {
			writeJSON(w, http.StatusOK, found)
			return
		}
	case hostverb.ExitGuardOff:
		writeError(w, http.StatusConflict, "the guard is not running on this box")
		return
	}
	writeJSON(w, http.StatusBadGateway, map[string]any{"error": "the lookup failed", "result": res})
}

type guardBody struct {
	Value string `json:"value"`
	Days  int    `json:"days"`
	List  string `json:"list"`
}

// guardAction runs one of the owner's actions, then answers with the new state.
func (s *Server) guardAction(build func(scripts string, body guardBody) (hostverb.Verb, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.templateHasTool(hostverb.GuardTool) {
			writeError(w, http.StatusForbidden, "this box's template does not ship "+hostverb.GuardTool+" yet")
			return
		}
		var body guardBody
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		verb, err := build(s.cfg.Scripts(), body)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		res, err := s.runVerb(r.Context(), verb)
		if err != nil {
			s.verbError(w, err)
			return
		}
		switch res.ExitCode {
		case 0:
		case hostverb.ExitGuardOff:
			writeError(w, http.StatusConflict, "the guard is not running on this box")
			return
		default:
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": "the change was not applied", "result": res})
			return
		}
		out := map[string]any{"message": lastLine(res.Output)}
		// The new state, best effort: the change itself is done.
		if st, err := hostverb.GuardStatus(s.cfg.Scripts()); err == nil {
			if res, err := s.runVerb(r.Context(), st); err == nil && res.ExitCode == 0 {
				if status := lastJSONLine(res.Output); status != nil {
					out["status"] = status
				}
			}
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func lastLine(out string) string {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

func (s *Server) handleGuardUnban() http.HandlerFunc {
	return s.guardAction(func(scripts string, b guardBody) (hostverb.Verb, error) {
		return hostverb.GuardUnban(scripts, b.Value)
	})
}

func (s *Server) handleGuardAllow() http.HandlerFunc {
	return s.guardAction(func(scripts string, b guardBody) (hostverb.Verb, error) {
		return hostverb.GuardAllow(scripts, b.Value, b.Days)
	})
}

func (s *Server) handleGuardDisallow() http.HandlerFunc {
	return s.guardAction(func(scripts string, b guardBody) (hostverb.Verb, error) {
		return hostverb.GuardDisallow(scripts, b.Value, b.List)
	})
}
