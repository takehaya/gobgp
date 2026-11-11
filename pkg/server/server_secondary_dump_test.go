package server

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// The initial dump of a route server client does not depend on the FSM
// state: a secondary-route client gets its routes and the End-of-RIB marker
// like any other client, and nothing is sent to it by route propagation
// before it is established.
func TestGetBestFromLocalSecondaryRouteBeforeEstablished(t *testing.T) {
	for _, secondary := range []bool{false, true} {
		t.Run(map[bool]string{false: "normal", true: "secondary"}[secondary], func(t *testing.T) {
			ctx := context.Background()
			s := NewBgpServer()
			go s.Serve()
			require.NoError(t, s.StartBgp(ctx, &api.StartBgpRequest{
				Global: &api.Global{Asn: 65001, RouterId: "1.1.1.1", ListenPort: -1},
			}))

			newClient := func(address string, asn uint32, secondary bool) *peer {
				p := newPeerandInfo(t, 65001, asn, address, s.rsRib)
				p.fsm.lock.Lock()
				conf := p.fsm.pConf.ReadCopy()
				conf.RouteServer.Config.RouteServerClient = true
				conf.RouteServer.Config.SecondaryRoute = secondary
				conf.GracefulRestart.State.Enabled = true
				p.fsm.pConf.Update(&conf)
				p.fsm.lock.Unlock()
				p.tableId = p.ID()
				p.policy = s.policy
				p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_NONE})
				return p
			}
			targetAddr := netip.MustParseAddr("10.0.0.1")
			sourceAddr := netip.MustParseAddr("10.0.0.2")
			target := newClient(targetAddr.String(), 65002, secondary)
			target.fsm.state.Store(bgp.BGP_FSM_OPENCONFIRM)
			source := newClient(sourceAddr.String(), 65003, false)
			source.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
			require.NoError(t, s.policy.SetPolicyAssignment(source.TableID(), table.POLICY_DIRECTION_IMPORT, nil, table.ROUTE_TYPE_ACCEPT))
			require.NoError(t, s.policy.SetPolicyAssignment(target.TableID(), table.POLICY_DIRECTION_EXPORT, nil, table.ROUTE_TYPE_ACCEPT))
			require.NoError(t, s.mgmtOperation(func() error {
				s.neighborMap[targetAddr] = target
				s.neighborMap[sourceAddr] = source
				return nil
			}, true))
			t.Cleanup(func() {
				require.NoError(t, s.mgmtOperation(func() error {
					delete(s.neighborMap, targetAddr)
					delete(s.neighborMap, sourceAddr)
					return nil
				}, false))
				cleanInfiniteChannel(target.fsm.outgoingCh)
				cleanInfiniteChannel(source.fsm.outgoingCh)
				require.NoError(t, s.StopBgp(ctx, &api.StopBgpRequest{}))
			})

			nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("192.0.2.0/24"))
			require.NoError(t, err)
			nextHop, err := bgp.NewPathAttributeNextHop(source.peerInfo.Load().Address)
			require.NoError(t, err)
			attrs := []bgp.PathAttributeInterface{
				bgp.NewPathAttributeOrigin(0),
				bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{65003})}),
				nextHop,
			}
			path := table.NewPath(bgp.RF_IPv4_UC, source.peerInfo.Load(), bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
			require.NoError(t, s.mgmtOperation(func() error {
				s.propagateUpdate(source, []*table.Path{path})
				return nil
			}, true))
			// Not established: nothing is sent by propagation.
			assert.Equal(t, 0, target.fsm.outgoingCh.Len())

			var got []*table.Path
			require.NoError(t, s.mgmtOperation(func() error {
				s.getBestFromLocalCallback(target, []bgp.Family{bgp.RF_IPv4_UC}, true, true, func(paths, _ []*table.Path) {
					got = paths
				})
				return nil
			}, true))
			require.Len(t, got, 2)
			assert.Equal(t, "192.0.2.0/24", got[0].GetNlri().String())
			assert.False(t, got[0].IsEOR())
			assert.True(t, got[1].IsEOR())
		})
	}
}
