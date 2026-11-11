package server

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

const scriptedPeerAS = 65001

// scriptedPeer plays the remote BGP speaker of a server's only peer over
// real TCP connections, so that a test decides what is sent on each
// connection and in which order. The server listens on 127.0.0.1 and the
// peer uses 127.0.0.2, where it also listens for the server's connection.
type scriptedPeer struct {
	t          *testing.T
	s          *BgpServer
	id         netip.Addr
	serverPort int
	accepted   chan net.Conn
}

func newScriptedPeer(t *testing.T, serverID, peerID string) *scriptedPeer {
	t.Helper()

	l, err := net.Listen("tcp4", "127.0.0.2:0")
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	accepted := make(chan net.Conn, 8)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	t.Cleanup(func() {
		for {
			select {
			case c := <-accepted:
				c.Close()
			default:
				return
			}
		}
	})

	sl, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	serverPort := sl.Addr().(*net.TCPAddr).Port
	sl.Close()

	s := NewBgpServer()
	go s.Serve()
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:             scriptedPeerAS,
			RouterId:        serverID,
			ListenAddresses: []string{"127.0.0.1"},
			ListenPort:      int32(serverPort),
		},
	}))
	t.Cleanup(func() { _ = s.StopBgp(context.Background(), &api.StopBgpRequest{}) })

	n := &oc.Neighbor{
		Config: oc.NeighborConfig{
			NeighborAddress: netip.MustParseAddr("127.0.0.2"),
			PeerAs:          scriptedPeerAS,
		},
		Transport: oc.Transport{
			Config: oc.TransportConfig{
				LocalAddress: netip.MustParseAddr("127.0.0.1"),
				RemotePort:   uint16(l.Addr().(*net.TCPAddr).Port),
			},
		},
		Timers: oc.Timers{
			Config: oc.TimersConfig{
				HoldTime:          90,
				KeepaliveInterval: 30,
				ConnectRetry:      1,
			},
		},
		AfiSafis: []oc.AfiSafi{{
			Config: oc.AfiSafiConfig{AfiSafiName: oc.AFI_SAFI_TYPE_IPV4_UNICAST, Enabled: true},
		}},
	}
	require.NoError(t, s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: oc.NewPeerFromConfigStruct(n)}))

	return &scriptedPeer{
		t:          t,
		s:          s,
		id:         netip.MustParseAddr(peerID),
		serverPort: serverPort,
		accepted:   accepted,
	}
}

func (p *scriptedPeer) peer() *api.Peer {
	var peer *api.Peer
	_ = p.s.ListPeer(context.Background(), &api.ListPeerRequest{}, func(x *api.Peer) { peer = x })
	return peer
}

func (p *scriptedPeer) waitState(state api.PeerState_SessionState) {
	p.t.Helper()
	require.Eventually(p.t, func() bool {
		return p.peer().GetState().GetSessionState() == state
	}, 10*time.Second, 10*time.Millisecond, "the session never reached %s", state)
}

// accept returns the next connection that the server opened to the peer,
// the server's outgoing connection.
func (p *scriptedPeer) accept(timeout time.Duration) net.Conn {
	p.t.Helper()
	select {
	case c := <-p.accepted:
		p.t.Cleanup(func() { c.Close() })
		return c
	case <-time.After(timeout):
		p.t.Fatal("the server did not connect to the peer")
		return nil
	}
}

func (p *scriptedPeer) open(holdTime uint16) *bgp.BGPMessage {
	caps := bgp.NewOptionParameterCapability([]bgp.ParameterCapabilityInterface{
		bgp.NewCapMultiProtocol(bgp.RF_IPv4_UC),
		bgp.NewCapFourOctetASNumber(scriptedPeerAS),
	})
	m, err := bgp.NewBGPOpenMessage(scriptedPeerAS, holdTime, p.id, []bgp.OptionParameterInterface{caps})
	require.NoError(p.t, err)
	return m
}

func (p *scriptedPeer) send(c net.Conn, m *bgp.BGPMessage) {
	p.t.Helper()
	b, err := m.Serialize()
	require.NoError(p.t, err)
	require.NoError(p.t, c.SetWriteDeadline(time.Now().Add(5*time.Second)))
	_, err = c.Write(b)
	require.NoError(p.t, err)
}

func (p *scriptedPeer) recv(c net.Conn, timeout time.Duration) *bgp.BGPMessage {
	p.t.Helper()
	require.NoError(p.t, c.SetReadDeadline(time.Now().Add(timeout)))
	hdr, err := readAll(c, bgp.BGP_HEADER_LENGTH)
	require.NoError(p.t, err, "no message from the server")
	body, err := readAll(c, int(binary.BigEndian.Uint16(hdr[16:18]))-bgp.BGP_HEADER_LENGTH)
	require.NoError(p.t, err)
	m, err := bgp.ParseBGPMessage(append(hdr, body...))
	require.NoError(p.t, err)
	return m
}

func (p *scriptedPeer) expect(c net.Conn, typ uint8) *bgp.BGPMessage {
	p.t.Helper()
	m := p.recv(c, 5*time.Second)
	require.Equal(p.t, typ, m.Header.Type, "unexpected message %v", m.Body)
	return m
}

// expectClosed checks that the server closed c without sending anything.
func (p *scriptedPeer) expectClosed(c net.Conn) {
	p.t.Helper()
	require.NoError(p.t, c.SetReadDeadline(time.Now().Add(5*time.Second)))
	n, err := c.Read(make([]byte, 1))
	require.Equal(p.t, 0, n)
	require.Error(p.t, err)
	var ne net.Error
	if errors.As(err, &ne) {
		require.False(p.t, ne.Timeout(), "the server did not close the connection")
	}
}

// requireSessionOn checks that the established session runs on c.
func (p *scriptedPeer) requireSessionOn(c net.Conn) {
	p.t.Helper()
	var local, remote uint16
	_ = p.s.mgmtOperation(func() error {
		for _, peer := range p.s.neighborMap {
			tr := peer.fsm.pConf.ReadOnly().Transport.State
			local, remote = tr.LocalPort, tr.RemotePort
		}
		return nil
	}, true)
	require.Equal(p.t, uint16(c.RemoteAddr().(*net.TCPAddr).Port), local)
	require.Equal(p.t, uint16(c.LocalAddr().(*net.TCPAddr).Port), remote)
}
