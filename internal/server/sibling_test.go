package server

import "testing"

func TestSiblingHost(t *testing.T) {
	for _, c := range []struct{ host, want string }{
		{"mesh-console.alice.nsl.sh", "maison.alice.nsl.sh"},
		{"Mesh-Console.Alice.nsl.sh:443", "maison.alice.nsl.sh"},
		{"mesh-console-alice.nsl.sh", "maison-alice.nsl.sh"},
		{"mesh-console-1-2-3-4.sslip.io", "maison-alice.nsl.sh"},
		{"mesh-console-app:8080", "maison-alice.nsl.sh"},
		{"", "maison-alice.nsl.sh"},
		{"evil.com", "maison-alice.nsl.sh"},
		{"xalice.nsl.sh", "maison-alice.nsl.sh"},
	} {
		if got := siblingHost(c.host, "maison", "alice.nsl.sh"); got != c.want {
			t.Errorf("siblingHost(%q) = %q, want %q", c.host, got, c.want)
		}
	}
}
