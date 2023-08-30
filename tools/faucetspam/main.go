// nolint
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	iotago "github.com/iotaledger/iota.go/v3"
)

const (
	url = "https://faucet.tanglekit.de/api/enqueue"
	//url = "http://localhost:14265/api/plugins/faucet/enqueue"
)

// faucetEnqueueRequest defines the request for a POST RouteFaucetEnqueue REST API call.
type faucetEnqueueRequest struct {
	// The bech32 address.
	Address string `json:"address"`
}

// FaucetEnqueueResponse defines the response of a POST RouteFaucetEnqueue REST API call.
type FaucetEnqueueResponse struct {
	// The bech32 address.
	Address string `json:"address"`
	// The number of waiting requests in the queue.
	WaitingRequests int `json:"waitingRequests"`
}

func main() {

	for i := 0; i < 1; i++ {
		pubKey, privKey, err := ed25519.GenerateKey(nil)
		if err != nil {
			panic(err)
		}

		addr := iotago.Ed25519AddressFromPubKey(pubKey)

		fmt.Println("Your ed25519 private key: ", hex.EncodeToString(privKey))
		fmt.Println("Your ed25519 public key: ", hex.EncodeToString(pubKey))
		fmt.Println("Your ed25519 address: ", hex.EncodeToString(addr[:]))
		fmt.Println("Your bech32 address: ", addr.Bech32("atoi"))

		jsonValue, _ := json.Marshal(&faucetEnqueueRequest{
			Address: addr.Bech32("atoi"),
		})

		resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonValue))
		if err != nil {
			panic(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusAccepted {
			panic(fmt.Errorf("http status code: %d", resp.StatusCode))
		}

		responseBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			panic(fmt.Errorf("unable to read response: %w", err))
		}

		res := FaucetEnqueueResponse{}
		err = json.Unmarshal(responseBytes, &res)
		if err != nil {
			panic(fmt.Errorf("unable to unmarshal response: %w", err))
		}

		println(fmt.Sprintf("WaitingRequests: %d", res.WaitingRequests))

	}
}
