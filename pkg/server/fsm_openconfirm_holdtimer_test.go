package server

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// In OpenConfirm the hold timer and the keepalive timer run with the hold
// time negotiated with the OPEN that the connection received (RFC 4271
// Section 8.2.2), not with what a previous session negotiated, and not
// with nothing because no session was ever established.
func TestFSMHandlerOpenconfirm_HoldTimerFromReceivedOpen(t *testing.T) {
	tests := []struct {
		name string
		// what a previous session left in the negotiated timer state
		prevHoldTime float64
		// the hold time in the peer's OPEN
		peerHoldTime uint16
		// the peer's KEEPALIVE arrives after this long, zero for never
		keepaliveAfter time.Duration
		wantState      bgp.FSMState
	}{
		{"never established, no KEEPALIVE", 0, 3, 0, bgp.BGP_FSM_IDLE},
		{"previous session negotiated more, no KEEPALIVE", 90, 3, 0, bgp.BGP_FSM_IDLE},
		// The keepalive interval is 3 seconds, a third of the hold time.
		{"KEEPALIVE late but within the hold time", 0, 9, 4500 * time.Millisecond, bgp.BGP_FSM_ESTABLISHED},
		{"hold time zero runs no timer", 3, 0, 3500 * time.Millisecond, bgp.BGP_FSM_ESTABLISHED},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := NewMockConnection()
			p, h := makePeerAndHandler(m)
			t.Cleanup(func() { cleanPeerAndHandler(p, h) })

			conf := p.fsm.pConf.ReadCopy()
			conf.Timers.Config.HoldTime = 90
			conf.Timers.Config.KeepaliveInterval = 30
			conf.Timers.State.NegotiatedHoldTime = tt.prevHoldTime
			conf.Timers.State.KeepaliveInterval = tt.prevHoldTime / 3
			p.fsm.pConf.Update(&conf)
			open, err := bgp.NewBGPOpenMessage(65002, tt.peerHoldTime, netip.MustParseAddr("10.0.0.1"), nil)
			require.NoError(t, err)
			p.fsm.recvOpen = open

			type result struct {
				state  bgp.FSMState
				reason *fsmStateReason
				after  time.Duration
			}
			start := time.Now()
			done := make(chan result, 1)
			go func() {
				state, reason := h.openconfirm(t.Context())
				done <- result{state, reason, time.Since(start)}
			}()
			if tt.keepaliveAfter > 0 {
				time.AfterFunc(tt.keepaliveAfter, func() { m.PushBgpMessage(bgp.NewBGPKeepAliveMessage()) })
			}

			var r result
			select {
			case r = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("openconfirm() did not return")
			}
			require.Equal(t, tt.wantState, r.state)

			keepalives, notif := sentKeepalivesAndNotification(t, m)
			if tt.wantState == bgp.BGP_FSM_IDLE {
				require.Equal(t, fsmHoldTimerExpired, r.reason.Type)
				require.GreaterOrEqual(t, r.after, time.Duration(tt.peerHoldTime)*time.Second)
				// The mock records a message only after the write
				// returns; wait for the NOTIFICATION.
				require.Eventually(t, func() bool {
					_, notif = sentKeepalivesAndNotification(t, m)
					return notif != nil
				}, time.Second, 10*time.Millisecond)
				require.Equal(t, uint8(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED), notif.ErrorCode)
			} else {
				require.Nil(t, notif)
			}
			if tt.peerHoldTime == 0 {
				require.Zero(t, keepalives)
			} else {
				require.Eventually(t, func() bool {
					keepalives, _ = sentKeepalivesAndNotification(t, m)
					return keepalives >= 1
				}, time.Second, 10*time.Millisecond)
			}
		})
	}
}

// sentKeepalivesAndNotification returns the number of KEEPALIVEs and the last
// NOTIFICATION sent on m.
func sentKeepalivesAndNotification(t *testing.T, m *MockConnection) (int, *bgp.BGPNotification) {
	t.Helper()
	var keepalives int
	var notif *bgp.BGPNotification
	for _, b := range m.GetSentMessages() {
		msg, err := bgp.ParseBGPMessage(b)
		require.NoError(t, err)
		switch msg.Header.Type {
		case bgp.BGP_MSG_KEEPALIVE:
			keepalives++
		case bgp.BGP_MSG_NOTIFICATION:
			notif = msg.Body.(*bgp.BGPNotification)
		}
	}
	return keepalives, notif
}

// A peer that answers the OPEN but never sends a KEEPALIVE leaves the
// session in OpenConfirm. The server must end the connection when the hold
// time expires, and the session must then come up on a new connection.
func TestOpenConfirmHoldTimerExpiresAndReconnects(t *testing.T) {
	p := newScriptedPeer(t, "10.0.0.9", "10.0.0.1")

	out := p.accept(10 * time.Second)
	p.expect(out, bgp.BGP_MSG_OPEN)
	start := time.Now() // the hold timer starts after the OPEN arrives
	p.send(out, p.open(3))
	p.expect(out, bgp.BGP_MSG_KEEPALIVE) // the answer to the OPEN

	keepalives := 0
	for {
		m := p.recv(out, 10*time.Second)
		if m.Header.Type == bgp.BGP_MSG_KEEPALIVE {
			keepalives++
			continue
		}
		require.Equal(t, uint8(bgp.BGP_MSG_NOTIFICATION), m.Header.Type)
		require.Equal(t, uint8(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED), m.Body.(*bgp.BGPNotification).ErrorCode)
		break
	}
	require.GreaterOrEqual(t, time.Since(start), 3*time.Second)
	require.GreaterOrEqual(t, keepalives, 1)
	p.expectClosed(out)

	again := p.accept(30 * time.Second)
	p.expect(again, bgp.BGP_MSG_OPEN)
	p.send(again, p.open(90))
	p.expect(again, bgp.BGP_MSG_KEEPALIVE)
	p.send(again, bgp.NewBGPKeepAliveMessage())
	p.waitState(api.PeerState_SESSION_STATE_ESTABLISHED)
	p.requireSessionOn(again)
}

// When openconfirm() resolves a collision and moves to our own connection,
// the timers start again with the OPEN received on that connection.
func TestFSMHandlerOpenconfirm_CollisionRestartsTimers(t *testing.T) {
	incoming := NewMockConnection()
	outgoing := NewMockConnection()
	p, h := makePeerAndHandler(incoming)
	t.Cleanup(func() {
		cleanPeerAndHandler(p, h)
		incoming.Close()
		outgoing.Close()
	})
	p.fsm.gConf.Config.RouterId = netip.MustParseAddr("10.0.0.9")
	conf := p.fsm.pConf.ReadCopy()
	conf.Timers.Config.HoldTime = 90
	conf.Timers.Config.KeepaliveInterval = 30
	p.fsm.pConf.Update(&conf)

	// OpenConfirm on the incoming connection with a hold time of 90.
	inOpen, err := bgp.NewBGPOpenMessage(65002, 90, netip.MustParseAddr("10.0.0.1"), nil)
	require.NoError(t, err)
	p.fsm.recvOpen = inOpen
	// The OPEN on our connection, which is kept, has a hold time of 3.
	outOpen, err := bgp.NewBGPOpenMessage(65002, 3, netip.MustParseAddr("10.0.0.1"), nil)
	require.NoError(t, err)
	p.fsm.outgoingConnCh <- outgoingConn{conn: outgoing, open: outOpen}

	start := time.Now()
	type result struct {
		state  bgp.FSMState
		reason *fsmStateReason
	}
	done := make(chan result, 1)
	go func() {
		state, reason := h.openconfirm(t.Context())
		done <- result{state, reason}
	}()
	select {
	case r := <-done:
		require.Equal(t, bgp.BGP_FSM_IDLE, r.state)
		require.Equal(t, fsmHoldTimerExpired, r.reason.Type)
		require.GreaterOrEqual(t, time.Since(start), 3*time.Second)
	case <-time.After(10 * time.Second):
		t.Fatal("the hold time of the OPEN on our connection did not expire")
	}
	require.Same(t, outgoing, p.fsm.conn)
	// The KEEPALIVE that answers the OPEN, then at least one sent every
	// second, a third of the new hold time. The interval of the incoming
	// connection's OPEN would be 30 seconds.
	keepalives, _ := sentKeepalivesAndNotification(t, outgoing)
	require.GreaterOrEqual(t, keepalives, 2)
}
