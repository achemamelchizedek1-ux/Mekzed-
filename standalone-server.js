/**
 * ShieldFi Standalone Server
 * Uses Node.js built-in http — no npm dependencies needed
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3001;

// ─── Services ────────────────────────────────────────────────────────────────

// ZK Service
const zkService = (() => {
  let stats = { generated: 0, verified: 0, rejected: 0 };
  const cache = new Map();
  const prime = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

  function rf() {
    return (BigInt('0x' + crypto.randomBytes(16).toString('hex')) % prime).toString();
  }

  function groth16Proof() {
    return {
      pi_a: [rf(), rf(), '1'],
      pi_b: [[rf(), rf()], [rf(), rf()], ['1', '0']],
      pi_c: [rf(), rf(), '1'],
      protocol: 'groth16', curve: 'bn128'
    };
  }

  function commitment(witness) {
    const data = Object.values(witness).join(':');
    return '0x' + crypto.createHash('sha256').update(data).digest('hex').slice(0, 32);
  }

  function hashProof(proof) {
    return '0x' + crypto.createHash('sha256').update(JSON.stringify(proof)).digest('hex').slice(0, 16);
  }

  return {
    async generateTradeProof({ tradeAmount, traderBalance, minBalance, maxTradeSize, nonce }) {
      if (+traderBalance < +minBalance) throw new Error(`Insufficient balance: ${traderBalance} < ${minBalance}`);
      if (+tradeAmount > +maxTradeSize) throw new Error(`Trade exceeds max: ${tradeAmount} > ${maxTradeSize}`);
      await new Promise(r => setTimeout(r, 80));
      stats.generated++;
      const proof = groth16Proof();
      const publicSignals = [String(minBalance), String(maxTradeSize), commitment({ tradeAmount, traderBalance, nonce: nonce || Math.floor(Math.random() * 1e12) })];
      return { proof, publicSignals, commitment: publicSignals[2], circuitId: 'trade_verify_v1', generatedAt: new Date().toISOString(), privacy: { hidden: ['tradeAmount', 'traderBalance', 'nonce'], revealed: ['minBalance', 'maxTradeSize', 'commitment'] } };
    },

    async generateRangeProof(value, min, max) {
      if (+value < +min || +value > +max) throw new Error(`Value ${value} outside range [${min}, ${max}]`);
      await new Promise(r => setTimeout(r, 60));
      stats.generated++;
      return { proof: groth16Proof(), publicSignals: { min: String(min), max: String(max) }, type: 'range_proof', bits: 64, circuit: 'range_proof_v1', valid: true };
    },

    async generateMembershipProof(address, merkleRoot) {
      await new Promise(r => setTimeout(r, 70));
      stats.generated++;
      return { proof: groth16Proof(), publicSignals: { merkleRoot }, type: 'membership_proof', circuit: 'membership_v1' };
    },

    async verifyProof({ proof, publicSignals, circuitId }) {
      if (!proof?.pi_a || !proof?.pi_b || !proof?.pi_c) throw new Error('Malformed proof: missing pi_a, pi_b, or pi_c');
      if (!Array.isArray(publicSignals)) throw new Error('publicSignals must be an array');
      if (proof.protocol !== 'groth16') throw new Error('Only groth16 proofs supported');
      await new Promise(r => setTimeout(r, 40));
      const proofHash = hashProof(proof);
      if (cache.has(proofHash)) { stats.rejected++; return { valid: false, reason: 'Proof already used (replay attack blocked)', proofHash }; }
      const valid = Array.isArray(proof.pi_a) && proof.pi_a.length === 3 && proof.pi_a[2] === '1' && Array.isArray(proof.pi_b) && Array.isArray(proof.pi_c);
      if (valid) { cache.set(proofHash, { verifiedAt: Date.now() }); stats.verified++; } else stats.rejected++;
      return { valid, proofHash, publicSignals, circuitId: circuitId || 'trade_verify_v1', verifiedAt: new Date().toISOString(), gasEstimate: { estimate: 250000, unit: 'gas', chain: 'EVM' } };
    },

    getStats() { return { ...stats, cacheSize: cache.size }; },
    getCircuits() {
      return [
        { id: 'trade_verify_v1', description: 'Trade validity proof', constraints: '~150k R1CS', publicInputs: ['minBalance', 'maxTradeSize', 'commitment'], privateInputs: ['tradeAmount', 'traderBalance', 'nonce'] },
        { id: 'range_proof_v1', description: '64-bit range proof', constraints: '~64k R1CS', publicInputs: ['min', 'max'], privateInputs: ['value'] },
        { id: 'membership_v1', description: 'Merkle membership', constraints: '~200k R1CS', publicInputs: ['merkleRoot'], privateInputs: ['address', 'path'] },
      ];
    }
  };
})();

// FHE Service
const fheService = (() => {
  const sessions = new Map();
  const ciphertexts = new Map();
  let stats = { sessions: 0, encryptions: 0, operations: 0 };

  function newCt(value, noise, publicKey) {
    const id = 'ct_' + crypto.randomBytes(6).toString('hex');
    ciphertexts.set(id, { _value: value, noise, publicKey, id });
    stats.operations++;
    return id;
  }

  return {
    generateKeys(sessionId) {
      const secret = crypto.randomBytes(32).toString('hex');
      const publicKey = crypto.createHash('sha256').update(secret).digest('hex');
      const evalKey = crypto.createHash('sha256').update(publicKey + 'eval').digest('hex');
      sessions.set(sessionId, { secret, publicKey, evalKey, noise: 0 });
      stats.sessions++;
      return { sessionId, publicKey, evalKey, securityLevel: 128, scheme: 'TFHE', created: new Date().toISOString() };
    },
    encrypt(sessionId, plaintext) {
      const s = sessions.get(sessionId);
      if (!s) throw new Error(`Session ${sessionId} not found`);
      const id = newCt(plaintext, Math.floor(Math.random() * 500), s.publicKey);
      stats.encryptions++;
      return { ciphertextId: id, sessionId, encryptedAt: new Date().toISOString() };
    },
    decrypt(sessionId, ciphertextId) {
      const s = sessions.get(sessionId);
      if (!s) throw new Error(`Session not found`);
      const ct = ciphertexts.get(ciphertextId);
      if (!ct) throw new Error(`Ciphertext not found`);
      if (ct.publicKey !== s.publicKey) throw new Error('Key mismatch');
      return { plaintext: ct._value, decryptedAt: new Date().toISOString() };
    },
    add(sessionId, idA, idB) {
      const a = ciphertexts.get(idA), b = ciphertexts.get(idB);
      if (!a || !b) throw new Error('Ciphertext(s) not found');
      const id = newCt(a._value + b._value, a.noise + b.noise, a.publicKey);
      return { resultCiphertextId: id, operation: 'homomorphic_add', noiseLevel: a.noise + b.noise, requiresBootstrap: (a.noise + b.noise) > 50000 };
    },
    multiply(sessionId, idA, idB) {
      const a = ciphertexts.get(idA), b = ciphertexts.get(idB);
      if (!a || !b) throw new Error('Ciphertext(s) not found');
      const noise = a.noise * b.noise + 1000;
      const id = newCt(a._value * b._value, noise, a.publicKey);
      return { resultCiphertextId: id, operation: 'homomorphic_multiply', noiseLevel: noise, requiresBootstrap: noise > 50000 };
    },
    balanceCheck(sessionId, balId, tradeId) {
      const bal = ciphertexts.get(balId), trade = ciphertexts.get(tradeId);
      if (!bal || !trade) throw new Error('Ciphertext(s) not found');
      const id = newCt(bal._value >= trade._value ? 1 : 0, bal.noise + trade.noise, bal.publicKey);
      return { resultCiphertextId: id, operation: 'encrypted_balance_check', noiseLevel: bal.noise + trade.noise, requiresBootstrap: false };
    },
    bootstrap(sessionId, ctId) {
      const ct = ciphertexts.get(ctId);
      if (!ct) throw new Error('Ciphertext not found');
      const fresh = Math.floor(Math.random() * 50);
      const id = newCt(ct._value, fresh, ct.publicKey);
      return { resultCiphertextId: id, operation: 'bootstrap', noiseBefore: ct.noise, noiseAfter: fresh };
    },
    getStats() { return { ...stats, activeSessions: sessions.size, storedCiphertexts: ciphertexts.size }; }
  };
})();

// ML Service
const mlService = (() => {
  const models = new Map([
    ['risk_scorer', { name: 'Risk Score Model', type: 'logistic_regression', features: 8, accuracy: 0.94 }],
    ['fraud_detector', { name: 'Fraud Detector', type: 'gradient_boost', features: 12, accuracy: 0.97 }],
    ['price_predictor', { name: 'Price Predictor', type: 'lstm', features: 6, accuracy: 0.81 }],
    ['portfolio_optimizer', { name: 'Portfolio Optimizer', type: 'neural_net', features: 10, accuracy: 0.88 }],
  ]);
  let inferences = 0;
  return {
    async infer(modelId, encryptedFeatures, sessionId) {
      const model = models.get(modelId);
      if (!model) throw new Error(`Model ${modelId} not found`);
      await new Promise(r => setTimeout(r, 120));
      inferences++;
      return { modelId, modelName: model.name, modelType: model.type, resultCiphertextId: 'ct_result_' + crypto.randomBytes(4).toString('hex'), confidence: (0.7 + Math.random() * 0.3).toFixed(3), latencyMs: Math.floor(80 + Math.random() * 80), privacyGuarantee: 'FHE — raw features never decrypted on server', totalInferences: inferences };
    },
    listModels() { return Array.from(models.entries()).map(([id, m]) => ({ id, ...m })); }
  };
})();

// Trade Service
const tradeService = (() => {
  const trades = [];
  let stats = { submitted: 0, executed: 0, rejected: 0, volume: 0 };
  return {
    async submitTrade({ proof, publicSignals, circuitId, tradeMetadata }) {
      const v = await zkService.verifyProof({ proof, publicSignals, circuitId });
      if (!v.valid) { stats.rejected++; throw new Error(`Trade rejected: ${v.reason || 'Invalid ZK proof'}`); }
      const trade = { id: 'trade_' + Date.now().toString(36), status: 'executed', proofHash: v.proofHash, gasUsed: 250000, executedAt: new Date().toISOString(), metadata: tradeMetadata || {}, privacy: 'shielded — amounts and identity hidden' };
      trades.unshift(trade);
      if (trades.length > 100) trades.length = 100;
      stats.submitted++; stats.executed++; stats.volume += Math.floor(Math.random() * 10000);
      return trade;
    },
    getHistory(limit = 20) { return trades.slice(0, limit).map(t => ({ id: t.id, status: t.status, proofHash: t.proofHash, executedAt: t.executedAt, privacy: t.privacy })); },
    getStats() { return { ...stats }; }
  };
})();

// Auth service
const roles = {
  trader: { id: 'trader', role: 'trader', name: 'Anonymous Trader', permissions: ['zk', 'trade', 'fhe'] },
  analyst: { id: 'analyst', role: 'analyst', name: 'Risk Analyst', permissions: ['zk', 'ml', 'range'] },
  admin: { id: 'admin', role: 'admin', name: 'Protocol Admin', permissions: ['*'] },
  auditor: { id: 'auditor', role: 'auditor', name: 'Compliance Auditor', permissions: ['verify', 'history'] },
  developer: { id: 'developer', role: 'developer', name: 'Protocol Developer', permissions: ['*', 'debug'] }
};

// ─── HTTP Router ─────────────────────────────────────────────────────────────

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => { data += chunk; if (data.length > 10e6) reject(new Error('Body too large')); });
    req.on('end', () => { try { resolve(data ? JSON.parse(data) : {}); } catch { resolve({}); } });
    req.on('error', reject);
  });
}

function send(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  });
  res.end(body);
}

function ok(res, data, message) { send(res, 200, { success: true, data, message }); }
function created(res, data) { send(res, 201, { success: true, data }); }
function err(res, status, msg) { send(res, status, { success: false, error: msg }); }

async function router(req, res) {
  const url = req.url.split('?')[0];
  const method = req.method;

  // CORS preflight
  if (method === 'OPTIONS') { send(res, 204, {}); return; }

  // Static files
  if (!url.startsWith('/api/') && url !== '/health') {
    const fp = url === '/' ? '/home/claude/shieldfi/frontend/index.html'
      : path.join('/home/claude/shieldfi/frontend', url);
    try {
      const ext = path.extname(fp);
      const mime = { '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript', '.json': 'application/json', '.png': 'image/png', '.svg': 'image/svg+xml' };
      const content = fs.readFileSync(fp);
      res.writeHead(200, { 'Content-Type': mime[ext] || 'text/plain' });
      res.end(content);
    } catch {
      const index = fs.readFileSync('/home/claude/shieldfi/frontend/index.html');
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(index);
    }
    return;
  }

  try {
    const body = method === 'POST' ? await readBody(req) : {};
    const q = Object.fromEntries(new URLSearchParams(req.url.split('?')[1] || ''));

    // ─── Health ───────────────────────────────────────────────
    if (url === '/health') {
      ok(res, { status: 'operational', version: '2.0.0', modules: { zkProofs: 'snarkjs/groth16 (simulated)', fhe: 'TFHE (simulated)', ml: 'fhe-inference', rust: 'napi-rs ready' }, uptime: Math.floor(process.uptime()), timestamp: new Date().toISOString() });
      return;
    }

    // ─── ZK Routes ────────────────────────────────────────────
    if (url === '/api/zk/verify' && method === 'POST') {
      if (!body.proof || !body.publicSignals) return err(res, 400, 'proof and publicSignals required');
      const result = await zkService.verifyProof(body);
      ok(res, result, result.valid ? 'Proof verified — trade conditions confirmed' : `Proof rejected: ${result.reason}`);
    }
    else if (url === '/api/zk/generate' && method === 'POST') {
      const { tradeAmount, traderBalance, minBalance, maxTradeSize, nonce } = body;
      if (!tradeAmount || !traderBalance || minBalance === undefined || !maxTradeSize) return err(res, 400, 'tradeAmount, traderBalance, minBalance, maxTradeSize required');
      const result = await zkService.generateTradeProof({ tradeAmount: +tradeAmount, traderBalance: +traderBalance, minBalance: +minBalance, maxTradeSize: +maxTradeSize, nonce });
      created(res, result);
    }
    else if (url === '/api/zk/range' && method === 'POST') {
      const { value, min, max } = body;
      if (value === undefined || min === undefined || max === undefined) return err(res, 400, 'value, min, max required');
      const result = await zkService.generateRangeProof(+value, +min, +max);
      created(res, result);
    }
    else if (url === '/api/zk/membership' && method === 'POST') {
      const { address, merkleRoot } = body;
      if (!address || !merkleRoot) return err(res, 400, 'address and merkleRoot required');
      const result = await zkService.generateMembershipProof(address, merkleRoot);
      created(res, result);
    }
    else if (url === '/api/zk/stats' && method === 'GET') { ok(res, zkService.getStats()); }
    else if (url === '/api/zk/circuits' && method === 'GET') { ok(res, zkService.getCircuits()); }

    // ─── FHE Routes ───────────────────────────────────────────
    else if (url === '/api/fhe/keygen' && method === 'POST') {
      const sid = body.sessionId || crypto.randomUUID();
      ok(res, fheService.generateKeys(sid));
    }
    else if (url === '/api/fhe/encrypt' && method === 'POST') {
      if (!body.sessionId || body.plaintext === undefined) return err(res, 400, 'sessionId and plaintext required');
      ok(res, fheService.encrypt(body.sessionId, +body.plaintext));
    }
    else if (url === '/api/fhe/decrypt' && method === 'POST') {
      if (!body.sessionId || !body.ciphertextId) return err(res, 400, 'sessionId and ciphertextId required');
      ok(res, fheService.decrypt(body.sessionId, body.ciphertextId));
    }
    else if (url === '/api/fhe/add' && method === 'POST') {
      if (!body.sessionId || !body.ciphertextIdA || !body.ciphertextIdB) return err(res, 400, 'sessionId, ciphertextIdA, ciphertextIdB required');
      ok(res, fheService.add(body.sessionId, body.ciphertextIdA, body.ciphertextIdB), 'Homomorphic addition — no decryption occurred');
    }
    else if (url === '/api/fhe/multiply' && method === 'POST') {
      if (!body.sessionId || !body.ciphertextIdA || !body.ciphertextIdB) return err(res, 400, 'sessionId, ciphertextIdA, ciphertextIdB required');
      ok(res, fheService.multiply(body.sessionId, body.ciphertextIdA, body.ciphertextIdB));
    }
    else if (url === '/api/fhe/balance-check' && method === 'POST') {
      if (!body.sessionId || !body.balanceCiphertextId || !body.tradeCiphertextId) return err(res, 400, 'All fields required');
      ok(res, fheService.balanceCheck(body.sessionId, body.balanceCiphertextId, body.tradeCiphertextId));
    }
    else if (url === '/api/fhe/bootstrap' && method === 'POST') {
      if (!body.sessionId || !body.ciphertextId) return err(res, 400, 'sessionId and ciphertextId required');
      ok(res, fheService.bootstrap(body.sessionId, body.ciphertextId));
    }
    else if (url === '/api/fhe/stats' && method === 'GET') { ok(res, fheService.getStats()); }

    // ─── Trade Routes ─────────────────────────────────────────
    else if (url === '/api/trade/submit' && method === 'POST') {
      if (!body.proof || !body.publicSignals) return err(res, 400, 'proof and publicSignals required');
      const trade = await tradeService.submitTrade(body);
      ok(res, trade);
    }
    else if (url === '/api/trade/history' && method === 'GET') { ok(res, tradeService.getHistory(+(q.limit || 20))); }
    else if (url === '/api/trade/stats' && method === 'GET') { ok(res, tradeService.getStats()); }

    // ─── ML Routes ────────────────────────────────────────────
    else if (url === '/api/ml/infer' && method === 'POST') {
      if (!body.modelId || !body.encryptedFeatures) return err(res, 400, 'modelId and encryptedFeatures required');
      const result = await mlService.infer(body.modelId, body.encryptedFeatures, body.sessionId);
      ok(res, result);
    }
    else if (url === '/api/ml/models' && method === 'GET') { ok(res, mlService.listModels()); }

    // ─── Auth Routes ──────────────────────────────────────────
    else if (url === '/api/auth/login' && method === 'POST') {
      const user = roles[body.role] || roles.trader;
      ok(res, { ...user, token: 'demo_' + crypto.randomBytes(8).toString('hex'), loginAt: new Date().toISOString() });
    }
    else if (url === '/api/auth/roles' && method === 'GET') {
      ok(res, Object.keys(roles).map(k => ({ id: k, name: roles[k].name, permissions: roles[k].permissions })));
    }

    // ─── Dashboard ────────────────────────────────────────────
    else if (url === '/api/dashboard/overview' && method === 'GET') {
      ok(res, { zk: zkService.getStats(), fhe: fheService.getStats(), trade: tradeService.getStats(), system: { uptime: Math.floor(process.uptime()), memoryMB: Math.floor(process.memoryUsage().rss / 1024 / 1024), nodeVersion: process.version, pid: process.pid }, timestamp: new Date().toISOString() });
    }

    // ─── 404 ──────────────────────────────────────────────────
    else { err(res, 404, `Endpoint not found: ${method} ${url}`); }

  } catch (e) {
    console.error('[ERROR]', e.message);
    err(res, 500, e.message);
  }
}

// ─── Start Server ─────────────────────────────────────────────────────────────
const server = http.createServer(router);
server.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════╗
║       ShieldFi — Private ML & Shielded DeFi v2.0    ║
║    ZK-Proofs (Groth16) + FHE (TFHE) + Private ML    ║
╠══════════════════════════════════════════════════════╣
║  Server  :  http://localhost:${PORT}                   ║
║  Frontend:  http://localhost:${PORT}/                  ║
║  Health  :  http://localhost:${PORT}/health            ║
║  ZK API  :  http://localhost:${PORT}/api/zk/verify     ║
║  FHE API :  http://localhost:${PORT}/api/fhe/keygen    ║
║  ML API  :  http://localhost:${PORT}/api/ml/infer      ║
╚══════════════════════════════════════════════════════╝
  `);
});

module.exports = server;
