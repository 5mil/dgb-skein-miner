# dgb-skein-miner

A cross-platform **DigiByte Skein** CPU miner written in [Unison](https://www.unison-lang.org/), with a CLI interface intentionally compatible with SRBMiner.

---

## Quick Start

```sh
# Linux / macOS
./miner --algorithm skein --pool stratum+tcp://sgb.mining-dutch.nl:3032 --wallet YOUR_WALLET --worker rig1 --password x

# Windows
miner.exe --algorithm skein --pool stratum+tcp://sgb.mining-dutch.nl:3032 --wallet YOUR_WALLET --worker rig1 --password x
```

Or use a config file:

```sh
./miner --config-file config.json
```

---

## CLI Flags

| Flag | Description | Default |
|---|---|---|
| `--algorithm` | Hash algorithm (`skein`) | required |
| `--pool` | Pool URL `stratum+tcp://host:port` | required |
| `--wallet` | Wallet address | required |
| `--worker` | Worker/rig name | `rig0` |
| `--password` | Pool password | `x` |
| `--tls` | Enable TLS (`true`/`false`) | `false` |
| `--cpu-threads` | Number of CPU threads | auto |
| `--disable-gpu` | Disable GPU mining | `false` |
| `--disable-cpu` | Disable CPU mining | `false` |
| `--config-file` | Path to JSON config file | `config.json` |
| `--pools-file` | Path to failover pools file | `pools.json` |
| `--background` | Run as background process | `false` |
| `--log-file` | Path to log output file | none |
| `--api-port` | Enable stats API on port | disabled |

---

## Config File (`config.json`)

```json
{
  "algorithm": "skein",
  "pool": "stratum+tcp://sgb.mining-dutch.nl:3032",
  "wallet": "YOUR_WALLET_ADDRESS",
  "worker": "rig1",
  "password": "x",
  "cpu-threads": 4,
  "tls": false,
  "log-file": "miner.log"
}
```

---

## Failover Pools (`pools.json`)

```json
[
  { "pool": "stratum+tcp://sgb.mining-dutch.nl:3032", "wallet": "YOUR_WALLET", "worker": "rig1", "password": "x" },
  { "pool": "stratum+tcp://backup-pool.example.com:3032", "wallet": "YOUR_WALLET", "worker": "rig1", "password": "x" }
]
```

---

## Building

Requirements: [Unison UCM](https://www.unison-lang.org/install/)

```sh
git clone https://github.com/5mil/dgb-skein-miner
cd dgb-skein-miner
ucm run .base.main
```

Or compile to a standalone binary:

```sh
ucm compile .main ./miner
```

---

## Architecture

```
dgb-skein-miner/
├── src/
│   ├── Main.u           -- Entry point, CLI arg parsing
│   ├── Config.u         -- Config file and flag resolution
│   ├── Stratum.u        -- Stratum TCP/JSON-RPC protocol layer
│   ├── MinerLoop.u      -- Job dispatch, nonce iteration, share submission
│   ├── Hash/
│   │   ├── Skein.u      -- Pure Unison Skein-512 implementation
│   │   └── Native.u     -- FFI hook for native Skein backend
│   └── Stats.u          -- Hashrate, shares, API endpoint
├── config.json          -- Example config
├── pools.json           -- Example failover pools
├── start-mine.sh        -- Linux/macOS launcher
├── start-mine.bat       -- Windows launcher
└── README.md
```

---

## Algorithm

This miner targets the **Skein** algorithm used by [DigiByte (DGB)](https://digibyte.org/) on the Skein chain. Skein-512 is used as the hash function, based on the Threefish tweakable block cipher.

---

## License

MIT
