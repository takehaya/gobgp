package server

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// A path added or withdrawn on the sending server after it has handled its
// peer's move to ESTABLISHED (and read the initial table for it), but before
// the FSM loop stores the new state, must still reach the peer. The hook holds
// the sending FSM at exactly that point while the change is made.
func TestPathChangeRightAfterEstablishedReachesPeer(t *testing.T) {
	for _, tc := range []struct {
		name     string
		withdraw bool
	}{
		{name: "add", withdraw: false},
		{name: "withdraw", withdraw: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			senderID := netip.MustParseAddr("1.1.1.1")

			inWindow := make(chan struct{})
			release := make(chan struct{})
			var holdOnce sync.Once
			testHookAfterStateCallback = func(f *fsm, next bgp.FSMState) {
				if next != bgp.BGP_FSM_ESTABLISHED || f.gConf.Config.RouterId != senderID {
					return
				}
				holdOnce.Do(func() {
					close(inWindow)
					<-release
				})
			}
			t.Cleanup(func() { testHookAfterStateCallback = nil })

			sender := runNewServer(t, 1, senderID.String(), 10979)
			t.Cleanup(func() { _ = sender.StopBgp(ctx, &api.StopBgpRequest{}) })
			receiver := runNewServer(t, 1, "2.2.2.2", 20979)
			t.Cleanup(func() { _ = receiver.StopBgp(ctx, &api.StopBgpRequest{}) })
			releaseOnce := sync.OnceFunc(func() { close(release) })
			t.Cleanup(releaseOnce) // never leave the sending FSM held

			newPath := func(prefix string) *apiutil.Path {
				nh, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
				nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
				p, err := apiutil.NewPath(bgp.RF_IPv4_UC, nlri, false,
					[]bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh}, time.Now())
				require.NoError(t, err)
				return mustApi2apiutilPath(p)
			}
			const target, sentinel = "10.20.0.0/24", "10.99.0.0/24"

			if tc.withdraw {
				// In the rib before the session comes up, so the initial
				// table carries it.
				_, err := sender.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{newPath(target)}})
				require.NoError(t, err)
			}

			require.NoError(t, peerServers(t, ctx, []*BgpServer{sender, receiver},
				[]oc.AfiSafiType{oc.AFI_SAFI_TYPE_IPV4_UNICAST}))

			select {
			case <-inWindow:
			case <-time.After(10 * time.Second):
				t.Fatal("sending FSM never reached ESTABLISHED")
			}
			if tc.withdraw {
				require.NoError(t, sender.DeletePath(apiutil.DeletePathRequest{
					Paths: []*apiutil.Path{newPath(target)}}))
			} else {
				_, err := sender.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{newPath(target)}})
				require.NoError(t, err)
			}
			releaseOnce()

			// A path added once the sender reports the peer established is
			// sent after anything queued earlier on the same session, so when
			// it has arrived the receiver has also processed the change above.
			require.Eventually(t, func() bool {
				up := false
				_ = sender.mgmtOperation(func() error {
					for _, p := range sender.neighborMap {
						up = p.State() == bgp.BGP_FSM_ESTABLISHED
					}
					return nil
				}, true)
				return up
			}, 10*time.Second, 10*time.Millisecond, "sender never stored ESTABLISHED")
			_, err := sender.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{newPath(sentinel)}})
			require.NoError(t, err)

			received := func() map[string]bool {
				got := map[string]bool{}
				_ = receiver.mgmtOperation(func() error {
					for _, p := range receiver.neighborMap {
						for _, path := range p.adjRibIn.PathList([]bgp.Family{bgp.RF_IPv4_UC}, false) {
							got[path.GetNlri().String()] = true
						}
					}
					return nil
				}, true)
				return got
			}
			require.Eventually(t, func() bool { return received()[sentinel] },
				10*time.Second, 50*time.Millisecond, "sentinel path never arrived")

			got := received()[target]
			if tc.withdraw {
				require.False(t, got, "withdrawn %s is still in the receiver's Adj-RIB-In", target)
			} else {
				require.True(t, got, "added %s never reached the receiver", target)
			}
		})
	}
}
