---
description: INX-Faucet is a faucet application for test and development networks as well as for private networks.
image: /img/Banner/banner_hornet.png
keywords:
- IOTA Node
- Hornet Node
- INX
- Faucet
- IOTA
- Shimmer
- Node Software
- Welcome
- explanation
---

# Welcome to INX-Faucet

Faucets give tokens away. This is useful when you need to provide testers with tokens on a test network or when you want to distribute tokens on a private Tangle. INX-Faucet lets your node to function as a faucet.

## Setup

We recommend you to use the [Docker images](https://hub.docker.com/r/iotaledger/inx-faucet).

Faucets only make sense on private networks. For more details, see [Run a Private Tangle](https://wiki.iota.org/hornet/develop/how_tos/private_tangle).

To run your own faucet, you need to provide a private key containing funds to the faucet. To do this, you must launch the `inx-faucet` program while passing a `FAUCET_PRV_KEY` environment variable that contains the private key.

The faucet includes a generic web GUI that is reachable at `http://localhost:8091` by default.

## Configuration

INX-Faucet connects to the local Hornet instance by default.

You can find all the configuration options in the [configuration section](configuration.md).

## Source Code

The source code of the project is available on [GitHub](https://github.com/iotaledger/inx-faucet).