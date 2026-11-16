package certs

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"regexp"
	"strings"
	"time"
)

// Holder is who holds the key of the certificate a visitor is shown.
type Holder string

const (
	// HolderGateway: the mesh gateway, with its own *.<zone> (dash names, the
	// apex while the box has no trusted certificate) or its fallback
	// *.<user>.<zone> (dot names while the box has none, phase-1.1-gateway-tls.md §6.3)
	HolderGateway Holder = "gateway"
	HolderBox     Holder = "box" // this box's own Let's Encrypt certificate
	HolderUnknown Holder = "unknown"
)

// Outside is one handshake made like a visitor's: public DNS, port 443,
// verification on. It shows which certificate the internet sees for the name.
type Outside struct {
	Host     string     `json:"host"`
	Kind     Kind       `json:"kind"`
	Holder   Holder     `json:"holder,omitempty"`
	Issuer   string     `json:"issuer,omitempty"`
	NotAfter *time.Time `json:"notAfter,omitempty"`
	// Fingerprint is the SHA-256 browsers show in their certificate viewer.
	Fingerprint string `json:"fingerprint,omitempty"`
	// Verified: a browser accepts it (chain and name). The handshake is retried
	// without verification to still show what is served when it is not.
	Verified bool   `json:"verified"`
	Error    string `json:"error,omitempty"`
}

// The Mesh Router CA (cert0): never a browser certificate, so never a holder.
var meshCAIssuer = regexp.MustCompile(`(?i)mesh router`)

// HolderOf decides who holds the key of leaf, served on host of kind k.
// serverDomain is the mesh zone (nsl.sh).
//
//   - *.<zone> on a dash name or the apex: the gateway's own. The CA alone
//     tells nothing: the gateways order from ZeroSSL first and Let's Encrypt as
//     a backup.
//   - a certificate naming host itself (*.<user>.<zone>, <user>.<zone>): the
//     box's when Let's Encrypt issued it (boxes order nowhere else), else the
//     gateway's fallback (ZeroSSL). The gateway's Let's Encrypt backup looks like
//     the box's; the caller tells them apart with the box's own certificate
//     (Outside.AgainstBox).
func HolderOf(leaf *x509.Certificate, k Kind, host, serverDomain string) Holder {
	if leaf == nil {
		return HolderUnknown
	}
	issuer := leaf.Issuer.CommonName + " " + strings.Join(leaf.Issuer.Organization, " ")
	if meshCAIssuer.MatchString(issuer) {
		return HolderUnknown
	}
	zoneWide := false
	for _, n := range leaf.DNSNames {
		zoneWide = zoneWide || strings.EqualFold(n, "*."+serverDomain)
	}
	switch {
	case zoneWide && (k == KindDash || k == KindApex):
		return HolderGateway
	case zoneWide:
		return HolderUnknown // *.<zone> covers one label: not a dot name's
	case (k == KindDot || k == KindApex) && leaf.VerifyHostname(host) == nil:
		if letsEncrypt.MatchString(issuer) {
			return HolderBox
		}
		return HolderGateway
	}
	return HolderUnknown
}

// AgainstBox corrects a "box" verdict with the certificate the box serves itself
// (box, from the local handshake): when the box holds no Let's Encrypt
// certificate, what the internet sees can only be the gateway's (its Let's
// Encrypt backup fallback). Two different Let's Encrypt certificates stay "box":
// a renewal the outside has not seen yet is far likelier than the backup.
func (o *Outside) AgainstBox(box Box) {
	if o.Holder == HolderBox && box.Kind != "" && box.Kind != BoxLetsEncrypt {
		o.Holder = HolderGateway
	}
}

// ProbeOutside does a visitor's handshake with host:443.
func ProbeOutside(ctx context.Context, host string, k Kind, serverDomain string) Outside {
	o, _ := ProbeOutsideLeaf(ctx, host, k, serverDomain)
	return o
}

// ProbeOutsideLeaf is ProbeOutside that also returns the served leaf (nil when
// nothing was served).
func ProbeOutsideLeaf(ctx context.Context, host string, k Kind, serverDomain string) (Outside, *x509.Certificate) {
	o := Outside{Host: host, Kind: k}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	leaf, err := outsideHandshake(ctx, host, false)
	if err == nil {
		o.Verified = true
	} else {
		o.Error = err.Error()
		var verr *tls.CertificateVerificationError
		if !errors.As(err, &verr) {
			return o, nil // nothing was served: DNS, connect or handshake failure
		}
		if leaf, err = outsideHandshake(ctx, host, true); err != nil {
			return o, nil
		}
	}
	o.Issuer = issuerName(leaf)
	na := leaf.NotAfter
	o.NotAfter = &na
	o.Fingerprint = Fingerprint(leaf)
	o.Holder = HolderOf(leaf, k, host, serverDomain)
	return o, leaf
}

func outsideHandshake(ctx context.Context, host string, insecure bool) (*x509.Certificate, error) {
	d := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		// insecure only on the retry after a verification failure, to show
		// what was served; Verified stays false then.
		Config: &tls.Config{ServerName: host, InsecureSkipVerify: insecure}, //nolint:gosec // see above
	}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	peers := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(peers) == 0 {
		return nil, errors.New("no certificate presented")
	}
	return peers[0], nil
}
