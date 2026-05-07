# ShieldFi — Private ML & Shielded DeFi Platform

> ZK-Proofs (Groth16) + FHE (TFHE) + Private ML · 7 Products · 5 User Role Interfaces · Zero npm dependencies

## Quick Start

```bash
# 1. Start the backend (no npm install needed)
node standalone-server.js

# 2. Open the platform hub in your browser
open shieldfi-hub.html

# 3. Or launch the multi-role unified app directly
open shieldfi-app.html
```

## Files

| File | Description |
|------|-------------|
| `standalone-server.js` | Zero-dependency Node.js backend — all APIs built-in |
| `shieldfi-hub.html` | Platform landing page linking all 7 products |
| `shieldfi-app.html` | **Unified 5-role app** — role switcher + all tools in one |
| `p1-zkproof.html` | ZK Trade Prover (dark green terminal aesthetic) |
| `p2-fhe.html` | FHE Compute Engine (deep blue sci-fi aesthetic) |
| `p3-range.html` | Range Proof Studio (amber geometric aesthetic) |
| `p4-verify.html` | Proof Verifier (clean light-mode aesthetic) |
| `p5-shieldtrade.html` | Shield Trade (violet + live order book) |
| `p6-mlprivacy.html` | Private ML Inference (teal data science aesthetic) |
| `p7-dashboard.html` | Privacy Command Center (real-time monitoring) |

## API Endpoints (localhost:3001)

### ZK Proofs
- `POST /api/zk/verify` — **Verify a Groth16 ZK proof** (core endpoint)
- `POST /api/zk/generate` — Generate a trade proof
- `POST /api/zk/range` — Range proof: value ∈ [min, max]
- `POST /api/zk/membership` — Merkle membership proof
- `GET  /api/zk/circuits` — List available circuits
- `GET  /api/zk/stats` — Proof statistics

### FHE
- `POST /api/fhe/keygen` — Generate FHE session keys
- `POST /api/fhe/encrypt` — Encrypt a plaintext value
- `POST /api/fhe/decrypt` — Decrypt a ciphertext
- `POST /api/fhe/add` — Homomorphic addition (no decryption)
- `POST /api/fhe/multiply` — Homomorphic multiplication
- `POST /api/fhe/balance-check` — Enc(balance) ≥ Enc(amount)
- `POST /api/fhe/bootstrap` — Refresh ciphertext (reduce noise)

### Trade, ML, System
- `POST /api/trade/submit` — Submit ZK-gated shielded trade
- `GET  /api/trade/history` — Anonymized trade history
- `POST /api/ml/infer` — FHE-encrypted ML inference
- `GET  /api/ml/models` — List 4 available ML models
- `GET  /api/dashboard/overview` — All system stats
- `GET  /health` — System health check

## Test the Core Endpoint

```bash
curl -X POST http://localhost:3001/api/zk/verify \
  -H "Content-Type: application/json" \
  -d '{
    "proof": {
      "pi_a": ["111","222","1"],
      "pi_b": [["333","444"],["555","666"],["1","0"]],
      "pi_c": ["777","888","1"],
      "protocol": "groth16",
      "curve": "bn128"
    },
    "publicSignals": ["1000","100000","0xabcdef"],
    "circuitId": "trade_verify_v1"
  }'
```

## 5 User Role Interfaces

| Role | Theme | Access |
|------|-------|--------|
| Trader | Green | ZK proofs, FHE compute, shielded trades |
| ML Analyst | Indigo | Private ML inference, FHE sessions, range proofs |
| Protocol Admin | Amber | Full access, circuit config, key management |
| Auditor | Cyan | Verify proofs, trade history, compliance |
| Developer | Pink | API explorer, debug tools, circuit viewer |

## Production Upgrades

- Replace ZK simulation with `snarkjs.groth16.fullProve()` + compiled `.wasm` + `.zkey`
- Replace FHE simulation with `node-seal` (Microsoft SEAL) or `tfhe-rs` via WASM  
- Deploy `Groth16Verifier.sol` on-chain for trustless verification
- Add Rust performance layer via `napi-rs` for witness generation
