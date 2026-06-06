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

	// No source address but a TLV: the draft-01 framing has no TLVs, so the
	// SourceAddressLength octet (0) is kept and the TLV follows it.
	tlv := NewMUPUnknownTLV(200, []byte{0xde, 0xad})
	nlri3 := NewMUPType1SessionTransformedRoute(rd, prefix, teid, 9, ep, nil, tlv)
	buf3, err := nlri3.Serialize()
	if err != nil {
		t.Fatalf("serialize with TLV: %v", err)
	}
	if buf3[3] != 28 { // 23 + 1 (SourceAddressLength 0) + 4 (TLV)
		t.Fatalf("TLV NLRI length octet = %d, want 28", buf3[3])
	}
	if buf3[4+23] != 0 {
		t.Fatalf("SourceAddressLength octet = %d, want 0", buf3[4+23])
	}
	dec3 := &MUPNLRI{Afi: AFI_IP}
	if err := dec3.decodeFromBytes(buf3); err != nil {
		t.Fatalf("decode with TLV: %v", err)
	}
	r3 := dec3.RouteTypeData.(*MUPType1SessionTransformedRoute)
	if r3.SourceAddress != nil || len(r3.TLVs) != 1 {
		t.Fatalf("TLV decode: SourceAddress = %v, TLVs = %v", r3.SourceAddress, r3.TLVs)
	}

	// A source-less -03 route (SourceAddressLength octet 0, Length 24) from a
	// peer still decodes.
	buf4 := append(append([]byte{}, buf...), 0)
	buf4[3] = 24
	dec4 := &MUPNLRI{Afi: AFI_IP}
	if err := dec4.decodeFromBytes(buf4); err != nil {
		t.Fatalf("decode -03 without source: %v", err)
	}
	if r4 := dec4.RouteTypeData.(*MUPType1SessionTransformedRoute); r4.SourceAddress != nil || r4.EndpointAddress != ep {
		t.Fatalf("-03 decode mismatch: SourceAddress = %v, ep = %v", r4.SourceAddress, r4.EndpointAddress)
	}
}
