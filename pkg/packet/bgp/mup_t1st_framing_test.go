package bgp

import (
	"bytes"
	"net/netip"
	"testing"
)

// A received Type 1 ST route is sent again exactly as it was received, in
// either framing, and its NLRI Length always matches its content.
func TestMUPT1STReceivedFramingRoundTrip(t *testing.T) {
	head4 := []byte{
		0x01, 0x00, 0x03, 0x00, // 3GPP 5G, route type 3 (T1ST), Length (set below)
		0x00, 0x00, 0xfd, 0xe9, 0x00, 0x00, 0x00, 0x01, // RD 65001:1
		0x20, 0x0a, 0x01, 0x00, 0x01, // prefix 10.1.0.1/32
		0x00, 0x00, 0x01, 0x00, // TEID
		0x09,                         // QFI
		0x20, 0xac, 0x10, 0x00, 0x01, // endpoint 172.16.0.1
	}
	head6 := []byte{
		0x01, 0x00, 0x03, 0x00,
		0x00, 0x00, 0xfd, 0xe9, 0x00, 0x00, 0x00, 0x01,
		0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, // prefix 2001:db8:1::/64
		0x00, 0x00, 0x01, 0x00,
		0x09,
		0x80, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, // endpoint 2001:db8::1
	}
	src4 := []byte{0x20, 0xac, 0x10, 0x00, 0xfe}
	src6 := []byte{0x80, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfe}
	tlv := []byte{0xc8, 0x02, 0xde, 0xad} // unknown TLV 200 with 2 octets
	join := func(parts ...[]byte) []byte {
		var b []byte
		for _, p := range parts {
			b = append(b, p...)
		}
		return b
	}
	tests := []struct {
		name    string
		rf      Family
		buf     []byte
		wantLen uint8
	}{
		{"draft-01 without source", RF_MUP_IPv4, join(head4), 23},
		{"-03 without source (SourceAddressLength 0)", RF_MUP_IPv4, join(head4, []byte{0}), 24},
		{"with source", RF_MUP_IPv4, join(head4, src4), 28},
		{"without source, with TLV", RF_MUP_IPv4, join(head4, []byte{0}, tlv), 28},
		{"with source and TLV", RF_MUP_IPv4, join(head4, src4, tlv), 32},
		{"IPv6 draft-01 without source", RF_MUP_IPv6, join(head6), 39},
		{"IPv6 -03 without source", RF_MUP_IPv6, join(head6, []byte{0}), 40},
		{"IPv6 with source", RF_MUP_IPv6, join(head6, src6), 56},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := append([]byte{}, tt.buf...)
			buf[3] = byte(len(buf) - 4)
			if buf[3] != tt.wantLen {
				t.Fatalf("test input Length = %d, want %d", buf[3], tt.wantLen)
			}
			n, err := NLRIFromSlice(tt.rf, buf)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			mup := n.(*MUPNLRI)
			if got := mup.RouteTypeData.Len(); got != int(mup.Length) {
				t.Fatalf("route Len() = %d, NLRI Length = %d", got, mup.Length)
			}
			out, err := n.Serialize()
			if err != nil {
				t.Fatalf("serialize: %v", err)
			}
			if !bytes.Equal(out, buf) {
				t.Fatalf("sent\n%x\nwant the received\n%x", out, buf)
			}
		})
	}
}

// Routes the fork builds itself keep their framing: no SourceAddressLength
// octet without a source address and TLVs, whatever was decoded before.
func TestMUPT1STOriginatedFramingUnchanged(t *testing.T) {
	rd, _ := ParseRouteDistinguisher("65001:1")
	prefix := netip.MustParsePrefix("10.1.0.1/32")
	teid := netip.MustParseAddr("0.0.1.0")
	ep := netip.MustParseAddr("172.16.0.1")
	src := netip.MustParseAddr("172.16.0.254")
	tests := []struct {
		name    string
		nlri    *MUPNLRI
		wantLen uint8
	}{
		{"without source", NewMUPType1SessionTransformedRoute(rd, prefix, teid, 9, ep, nil), 23},
		{"with source", NewMUPType1SessionTransformedRoute(rd, prefix, teid, 9, ep, &src), 28},
		{"without source, with TLV", NewMUPType1SessionTransformedRoute(rd, prefix, teid, 9, ep, nil, NewMUPUnknownTLV(200, []byte{0xde, 0xad})), 28},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.nlri.Length != tt.wantLen {
				t.Fatalf("Length = %d, want %d", tt.nlri.Length, tt.wantLen)
			}
			out, err := tt.nlri.Serialize()
			if err != nil {
				t.Fatalf("serialize: %v", err)
			}
			if len(out) != 4+int(tt.wantLen) {
				t.Fatalf("serialized %d octets, want %d", len(out), 4+int(tt.wantLen))
			}
		})
	}
}
