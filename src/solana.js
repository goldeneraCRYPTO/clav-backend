const { Connection, Keypair, Transaction, VersionedTransaction } = require('@solana/web3.js');
const bs58 = require('bs58');

function makeConnection(rpcUrl) {
  return new Connection(rpcUrl, 'confirmed');
}

function keypairFromBase58Secret(secretBase58) {
  const bytes = bs58.decode(secretBase58);
  return Keypair.fromSecretKey(bytes);
}

function decodeTxBytes(transactionStr) {
  // Bags docs: launch tx is base58. Some endpoints return base64. Handle both.
  const looksBase58 = /^[1-9A-HJ-NP-Za-km-z]+$/.test(transactionStr);
  if (looksBase58) return Buffer.from(bs58.decode(transactionStr));
  return Buffer.from(transactionStr, 'base64');
}

function signTxToBytes(secretBase58, transactionStr) {
  const kp = keypairFromBase58Secret(secretBase58);
  const raw = decodeTxBytes(transactionStr);

  try {
    const vtx = VersionedTransaction.deserialize(raw);
    vtx.sign([kp]);
    return Buffer.from(vtx.serialize());
  } catch (_) {
    const tx = Transaction.from(raw);
    tx.sign(kp);
    return Buffer.from(tx.serialize());
  }
}

async function sendSignedBytes(connection, txBytes) {
  const sig = await connection.sendRawTransaction(txBytes, {
    skipPreflight: false,
    maxRetries: 3,
  });
  await connection.confirmTransaction(sig, 'confirmed');
  return sig;
}

module.exports = {
  makeConnection,
  signTxToBytes,
  sendSignedBytes,
};
