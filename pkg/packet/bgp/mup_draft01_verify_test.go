package bgp

import (
	"net/netip"
	"testing"
)

// Verifies the draft-01 framing patch: a T1ST without a source address must
// serialize without a trailing SourceAddressLength octet (23-byte route, NLRI
// Length 0x17) and round-trip, while a T1ST that carries a source address keeps
// the -03 framing.
func TestMUPT1STDraft01Framing(t *testing.T) {
	rd, _ := ParseRouteDistinguisher("65001:1")
	prefix := netip.MustParsePrefix("10.1.0.1/32")
	teid := netip.MustParseAddr("0.0.1.0")
	ep := netip.MustParseAddr("172.16.0.1")

	// No source address -> draft-01 framing.
	nlri := NewMUPType1SessionTransformedRoute(rd, prefix, teid, 9, ep, nil)
	buf, err := nlri.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	// 4-byte MUPNLRI header (arch, route-type, length) + route bytes.
	if buf[3] != 23 {
		t.Fatalf("draft-01 NLRI length octet = %d, want 23", buf[3])
	}
	if got := len(buf); got != 4+23 {
		t.Fatalf("draft-01 total len = %d, want 27", got)
	}
	// Round-trip.
	dec := &MUPNLRI{Afi: AFI_IP}
	if err := dec.decodeFromBytes(buf); err != nil {
		t.Fatalf("decode draft-01: %v", err)
	}
	r := dec.RouteTypeData.(*MUPType1SessionTransformedRoute)
	if r.SourceAddress != nil {
		t.Fatalf("draft-01 decode: SourceAddress = %v, want nil", r.SourceAddress)
	}
	if r.EndpointAddress != ep || r.Prefix != prefix {
		t.Fatalf("draft-01 decode mismatch: ep=%v prefix=%v", r.EndpointAddress, r.Prefix)
	}

	// With a source address -> draft-03 framing is preserved.
	src := netip.MustParseAddr("172.16.0.254")
	nlri2 := NewMUPType1SessionTransformedRoute(rd, prefix, teid, 9, ep, &src)
	buf2, err := nlri2.Serialize()
	if err != nil {
		t.Fatalf("serialize with src: %v", err)
	}
	if buf2[3] != 28 { // 23 + 1 (SourceAddressLength) + 4 (IPv4 source)
		t.Fatalf("draft-03 NLRI length octet = %d, want 28", buf2[3])
	}
	dec2 := &MUPNLRI{Afi: AFI_IP}
	if err := dec2.decodeFromBytes(buf2); err != nil {
		t.Fatalf("decode draft-03: %v", err)
	}
	r2 := dec2.RouteTypeData.(*MUPType1SessionTransformedRoute)
	if r2.SourceAddress == nil || *r2.SourceAddress != src {
		t.Fatalf("draft-03 decode: SourceAddress = %v, want %v", r2.SourceAddress, src)
	}
}
