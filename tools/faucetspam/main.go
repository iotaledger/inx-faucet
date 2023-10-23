// nolint
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/iotaledger/inx-faucet/pkg/faucet"
	iotago "github.com/iotaledger/iota.go/v4"
	"github.com/iotaledger/iota.go/v4/tpkg"
)

const (
	url = "http://localhost:8088/api/enqueue"

	network = iotago.PrefixTestnet
)

func main() {

	for i := 0; i < 1000; i++ {
		pubKey := ed25519.PublicKey(tpkg.RandBytes(32))

		addr := iotago.Ed25519AddressFromPubKey(pubKey)

		fmt.Println("Your ed25519 public key: ", hex.EncodeToString(pubKey))
		fmt.Println("Your ed25519 address: ", hex.EncodeToString(addr[:]))
		fmt.Println("Your bech32 address: ", addr.Bech32(network))

		jsonValue, _ := json.Marshal(&faucet.EnqueueRequest{
			Address: addr.Bech32(network),
		})

		resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonValue))
		if err != nil {
			panic(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusAccepted {
			panic(fmt.Errorf("http status code: %d", resp.StatusCode))
		}

		responseBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			panic(fmt.Errorf("unable to read response: %w", err))
		}

		res := faucet.EnqueueResponse{}
		err = json.Unmarshal(responseBytes, &res)
		if err != nil {
			panic(fmt.Errorf("unable to unmarshal response: %w", err))
		}

		println(fmt.Sprintf("WaitingRequests: %d", res.WaitingRequests))

	}
}
