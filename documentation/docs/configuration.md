---
description: This section describes the configuration parameters and their types for INX-Faucet.
keywords:
- IOTA Node
- Hornet Node
- Faucet
- Configuration
- JSON
- Customize
- Config
- reference
---


# Core Configuration

INX-Faucet uses a JSON standard format as a config file. If you are unsure about JSON syntax, you can find more information in the [official JSON specs](https://www.json.org).

You can change the path of the config file by using the `-c` or `--config` argument while executing `inx-faucet` executable.

For example:
```bash
inx-faucet -c config_defaults.json
```

You can always get the most up-to-date description of the config parameters by running:

```bash
inx-faucet -h --full
```
## <a id="app"></a> 1. Application

| Name            | Description                                                                                            | Type    | Default value |
| --------------- | ------------------------------------------------------------------------------------------------------ | ------- | ------------- |
| checkForUpdates | Whether to check for updates of the application or not                                                 | boolean | true          |
| stopGracePeriod | The maximum time to wait for background processes to finish during shutdown before terminating the app | string  | "5m"          |

Example:

```json
  {
    "app": {
      "checkForUpdates": true,
      "stopGracePeriod": "5m"
    }
  }
```

## <a id="inx"></a> 2. INX

| Name    | Description                            | Type   | Default value    |
| ------- | -------------------------------------- | ------ | ---------------- |
| address | The INX address to which to connect to | string | "localhost:9029" |

Example:

```json
  {
    "inx": {
      "address": "localhost:9029"
    }
  }
```

## <a id="faucet"></a> 3. Faucet

| Name                           | Description                                                                                                                  | Type   | Default value    |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------- | ------ | ---------------- |
| amount                         | The amount of funds the requester receives                                                                                   | uint   | 1000000000       |
| smallAmount                    | The amount of funds the requester receives if the target address has more funds than the faucet amount and less than maximum | uint   | 100000000        |
| maxAddressBalance              | The maximum allowed amount of funds on the target address                                                                    | uint   | 2000000000       |
| maxOutputCount                 | The maximum output count per faucet message                                                                                  | int    | 128              |
| tagMessage                     | The faucet transaction tag payload                                                                                           | string | "HORNET FAUCET"  |
| batchTimeout                   | The maximum duration for collecting faucet batches                                                                           | string | "2s"             |
| bindAddress                    | The bind address on which the faucet website can be accessed from                                                            | string | "localhost:8091" |
| [rateLimit](#faucet_ratelimit) | Configuration for rateLimit                                                                                                  | object |                  |

### <a id="faucet_ratelimit"></a> RateLimit

| Name        | Description                                     | Type   | Default value |
| ----------- | ----------------------------------------------- | ------ | ------------- |
| period      | The period for rate limiting                    | string | "5m"          |
| maxRequests | The maximum number of requests per period       | int    | 10            |
| maxBurst    | Additional requests allowed in the burst period | int    | 20            |

Example:

```json
  {
    "faucet": {
      "amount": 1000000000,
      "smallAmount": 100000000,
      "maxAddressBalance": 2000000000,
      "maxOutputCount": 128,
      "tagMessage": "HORNET FAUCET",
      "batchTimeout": "2s",
      "bindAddress": "localhost:8091",
      "rateLimit": {
        "period": "5m",
        "maxRequests": 10,
        "maxBurst": 20
      }
    }
  }
```

## <a id="profiling"></a> 4. Profiling

| Name        | Description                                       | Type    | Default value    |
| ----------- | ------------------------------------------------- | ------- | ---------------- |
| enabled     | Whether the profiling plugin is enabled           | boolean | false            |
| bindAddress | The bind address on which the profiler listens on | string  | "localhost:6060" |

Example:

```json
  {
    "profiling": {
      "enabled": false,
      "bindAddress": "localhost:6060"
    }
  }
```

