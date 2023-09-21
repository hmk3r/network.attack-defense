package client

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"ethz.ch/netsec/isl/handout/attack/server"
	"github.com/netsec-ethz/scion-apps/pkg/appnet"
	"github.com/scionproto/scion/go/lib/snet"
)

// Example on how to generate a payload with the public meow API
func GenerateClientPayload() []byte {
	// Choose which request to send
	d := `"H"`

	// Use API to build request - haha no
	// request := server.NewRequest(q, flags...)
	// server.SetID(10)(request)
	// serialize the request with the API Marshal function
	// d, err := request.MarshalJSON()

	return []byte(d)
}

// Client is a simple udp-client example which speaks udp over scion through the appnet API.
// The payload is sent to the given address exactly once and the answer is printed to
// standard output.
func Client(ctx context.Context, serverAddr *snet.UDPAddr, payload []byte) (err error) {

	/* Appnet is a high level API provided by the scionlab team which facilitates sending and
	receiving scion traffic. The most common use cases are covered, but solving this lab exercise
	will need more fine grained control than appnet provides.
	*/

	fmt.Println("Next hop ", serverAddr.NextHop.String())

	conn, err := appnet.DialAddr(serverAddr)
	if err != nil {
		fmt.Println("CLIENT: Dial produced an error.", err)
		return
	}
	defer conn.Close()
	n, err := conn.Write(payload)
	if err != nil {
		fmt.Println("CLIENT: Write produced an error.", err)
		return
	}

	fmt.Printf("CLIENT: Packet-written: bytes=%d addr=%s\n", n, serverAddr.String())
	buffer := make([]byte, server.MaxBufferSize)

	// Setting a read deadline makes sure the program doesn't get stuck waiting for an
	// answer from the server for too long.
	deadline := time.Now().Add(time.Second * 3)
	err = conn.SetReadDeadline(deadline)
	if err != nil {
		fmt.Println("CLIENT: SetReadDeadline produced an error.", err)
		return
	}

	nRead, addr, err := conn.ReadFrom(buffer)
	if err != nil {
		fmt.Println("CLIENT: Error reading from connection.", err)
		return
	}

	fmt.Printf("CLIENT: Packet-received: bytes=%d from=%s\n",
		nRead, addr.String())
	var answer string
	json.Unmarshal(buffer[:nRead], &answer)
	fmt.Printf("CLIENT:The answer was: \n%s", answer)

	return
}
