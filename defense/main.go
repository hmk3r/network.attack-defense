package main

import (
	"encoding/binary"
	"fmt"
	"time"

	"ethz.ch/netsec/isl/handout/defense/lib"
	"github.com/scionproto/scion/go/lib/slayers"
)

type AddrTableKey string

type AddrMetadata struct {
	PacketsReceived uint64 // Amount of packets seen for this address
	Filtered        bool   // Whether the packets should be dropped
	DropUntil       time.Time
}

const (
	// Global constants
	OBSERVED_CLIENTS_NUMBER = 4
	IP_PACKETS_MAX_PS       = 3
	AS_PACKETS_MAX_PS       = (OBSERVED_CLIENTS_NUMBER + 1) * IP_PACKETS_MAX_PS
	AS_COOLDOWN             = 5 * time.Second
	// Add cooldown per IP, attackers may spoof a legitimate client's IP,
	// and we don't want to perma block them
	IP_COOLDOWN = 12 * time.Second
)

var (
	// Here, you can define variables that keep state for your firewall
	addrTable map[AddrTableKey]AddrMetadata
	nextPurge time.Time
)

// This function receives all packets destined to the customer server.
//
// Your task is to decide whether to forward or drop a packet based on the
// headers and payload.
// References for the given packet types:
// - SCION header
//   https://pkg.go.dev/github.com/scionproto/scion/go/lib/slayers#SCION
// - UDP header
//   https://pkg.go.dev/github.com/scionproto/scion/go/lib/slayers#UDP
//
func filter(scion slayers.SCION, udp slayers.UDP, payload []byte) bool {
	// Print packet contents (disable this before submitting your code)
	// prettyPrintSCION(scion)
	// prettyPrintUDP(udp)

	// IP := binary.BigEndian.Uint32(scion.RawSrcAddr)

	// fmt.Printf("%s,%d,%d,%s\n", scion.SrcIA.String(), IP, udp.SrcPort, string(payload))
	// Initial Thoughts
	// 1. Since computing nonces is computationally cheap, and signing is expensive
	// there exists an application-layer attack - resource exhaustion

	// 2. No point in looking at nonces - they are random, and any attacker with common sense
	// will have a different nonce for each packet

	// 3. Checking UDP ports may be an edge case, e.g. if a legitimate client tries to access the website
	// from the same IP an attack is launched

	// 5. Generalise to the lowest layer possible, look at minimal information

	// 6. Look for high number of requests from IPs, ASes, etc. Upon exceeding a threshold,
	// the AS/IP should be temporary or permanently blocked

	// 7. Threshold formulation ideas:
	//     - 400ms processing per message - reference point for threshold
	//     - "couple of seconds to respond" - queue

	// Observations from attack analysis:

	// General: All nonces are unique

	// Attack 1: Many hosts make > 500 requests. Other hosts(possibly the legitimate ones) send few, ~ 15-16
	// Ports are reused

	// Attack 2: Many hosts make 6 requests. Single cases (possibly the legitimate clients) make ~ 15-16
	// Some ports are reused

	// Attack 3: Attackers use an IP only once. Ports/IPs are likely reused only by legitimate clients

	// Grafana shows that clients max out at about 2.2 request per second, say 3 for a good measure
	// Firewall receives about 130 packets/s
	// So allow each ip to send a maximum of ~3 packs a second before blocking
	// And each AS 4 * 3 ~ 12 packs a second, as clients seem to be in the same one
	currTime := time.Now()

	// Reset the number of packets if the thresholds per second hasn't been exceeded
	if currTime.After(nextPurge) {
		for k, v := range addrTable {
			if !v.Filtered {
				v.PacketsReceived = 0
				v.DropUntil = currTime.Add(420 * 69 * time.Second)
				addrTable[k] = v
			}
		}
		nextPurge = currTime.Add(time.Second)
	}

	keyAS := AddrTableKey(scion.SrcIA.String())

	keyIP := AddrTableKey(
		fmt.Sprintf(
			"%s,%d",
			scion.SrcIA.String(),
			binary.BigEndian.Uint32(scion.RawSrcAddr),
		),
	)

	addrMetadata, exists := addrTable[keyIP]

	if !exists || currTime.After(addrMetadata.DropUntil) {
		addrTable[keyIP] = AddrMetadata{
			PacketsReceived: 0,
			Filtered:        false,
			// add arbitrary drop time to not enter this if every time(Branch predictor go brrrrrr)
			DropUntil: currTime.Add(420 * 69 * time.Second), // i'm a child
		}
		addrMetadata = addrTable[keyIP]
	}

	asMetadata, exists := addrTable[keyAS]

	// boolean short circuit
	if !exists || currTime.After(asMetadata.DropUntil) {
		addrTable[keyAS] = AddrMetadata{
			PacketsReceived: 0,
			// add arbitrary drop time to not enter this if every time(Branch predictor go brrrrrr)
			DropUntil: currTime.Add(420 * 69 * time.Second), // i'm a child
			Filtered:  false,
		}
		asMetadata = addrTable[keyAS]
	}

	addrMetadata.PacketsReceived++
	// Attack 3 defence: Ignore the first packet. Legitimate hosts will likely retry,
	// So start accepting packets from a host if they try one more time
	wasFiltered := asMetadata.Filtered
	// Attack 1 defence: Ignore packets if they exceed a high-packet number threshold
	addrMetadata.Filtered = addrMetadata.PacketsReceived < 2 || addrMetadata.PacketsReceived > IP_PACKETS_MAX_PS

	if addrMetadata.Filtered && !wasFiltered {
		addrMetadata.DropUntil = currTime.Add(IP_COOLDOWN)
	}

	addrTable[keyIP] = addrMetadata

	// Attack 2 seems to be originating from two ASes, filter on ASes

	// Do not give the whole AS a bad rep just because a single address in it acts badly
	if !addrMetadata.Filtered {
		asMetadata.PacketsReceived++
	}
	wasFiltered = asMetadata.Filtered
	asMetadata.Filtered = asMetadata.PacketsReceived > AS_PACKETS_MAX_PS

	// Some clients seem to be in the malicious ASes, so we should give them a chance too
	// somehow. Try to set an expiry time on the filter?

	if asMetadata.Filtered && !wasFiltered {
		asMetadata.DropUntil = currTime.Add(AS_COOLDOWN)
	}

	addrTable[keyAS] = asMetadata

	// true  -> forward packet
	// false -> drop packet

	return !(addrMetadata.Filtered || asMetadata.Filtered)
}

func init() {
	addrTable = make(map[AddrTableKey]AddrMetadata)
	nextPurge = time.Now().Add(time.Second)
	// fmt.Println("ISD-AS,IP,Port,Payload")
}

func main() {
	// Start the firewall. Code after this line will not be executed
	lib.RunFirewall(filter)
}
