import { ml_kem, ml_dsa, slh_dsa, utils } from "./index.js";

// Helper function to run benchmarks
function benchmark(testFn, iterations = 100) {
  // Warmup
  for (let i = 0; i < 5; i++) {
    testFn();
  }

  const times = [];
  const start = performance.now();
  
  // Run the benchmark
  for (let i = 0; i < iterations; i++) {
    const startIter = performance.now();
    testFn();
    times.push(performance.now() - startIter);
  }
  
  const totalTime = performance.now() - start;
  const opsPerSec = Math.floor((iterations / totalTime) * 1000);
  const microSecsPerOp = Math.floor((totalTime / iterations) * 1000);
  
  return {
    opsPerSec,
    microSecsPerOp,
    totalTime
  };
}

// Format results nicely
function formatResults(category, operation, results) {
  console.log(`${operation}`);
  const items = Object.entries(results);
  
  for (let i = 0; i < items.length; i++) {
    const [name, result] = items[i];
    const prefix = i === items.length - 1 ? '└─' : '├─';
    console.log(`${prefix}${name} x ${result.opsPerSec.toLocaleString()} ops/sec @ ${result.microSecsPerOp}μs/op`);
  }
}

// Run all benchmarks
async function runBenchmarks() {
  console.log("Running benchmarks...\n");
  
  // ----------------- ML-KEM Benchmarks -----------------
  console.log("ML-KEM");
  
  // Keygen
  const kemKeygenResults = {
    "ML-KEM-512": benchmark(() => ml_kem.ml_kem512.keygen()),
    "ML-KEM-768": benchmark(() => ml_kem.ml_kem768.keygen()),
    "ML-KEM-1024": benchmark(() => ml_kem.ml_kem1024.keygen())
  };
  formatResults("ML-KEM", "keygen", kemKeygenResults);
  
  // Pre-generate keys for encrypt/decrypt benchmarks
  const kem512Keys = ml_kem.ml_kem512.keygen();
  const kem768Keys = ml_kem.ml_kem768.keygen();
  const kem1024Keys = ml_kem.ml_kem1024.keygen();
  
  // Encrypt
  const kemEncryptResults = {
    "ML-KEM-512": benchmark(() => ml_kem.ml_kem512.encapsulate(kem512Keys.publicKey)),
    "ML-KEM-768": benchmark(() => ml_kem.ml_kem768.encapsulate(kem768Keys.publicKey)),
    "ML-KEM-1024": benchmark(() => ml_kem.ml_kem1024.encapsulate(kem1024Keys.publicKey))
  };
  formatResults("ML-KEM", "encrypt", kemEncryptResults);
  
  // Generate ciphertexts for decrypt benchmarks
  const { cipherText: kem512CipherText } = ml_kem.ml_kem512.encapsulate(kem512Keys.publicKey);
  const { cipherText: kem768CipherText } = ml_kem.ml_kem768.encapsulate(kem768Keys.publicKey);
  const { cipherText: kem1024CipherText } = ml_kem.ml_kem1024.encapsulate(kem1024Keys.publicKey);
  
  // Decrypt
  const kemDecryptResults = {
    "ML-KEM-512": benchmark(() => ml_kem.ml_kem512.decapsulate(kem512CipherText, kem512Keys.secretKey)),
    "ML-KEM-768": benchmark(() => ml_kem.ml_kem768.decapsulate(kem768CipherText, kem768Keys.secretKey)),
    "ML-KEM-1024": benchmark(() => ml_kem.ml_kem1024.decapsulate(kem1024CipherText, kem1024Keys.secretKey))
  };
  formatResults("ML-KEM", "decrypt", kemDecryptResults);
  
  // ----------------- ML-DSA Benchmarks -----------------
  console.log("\nML-DSA");
  
  // Keygen
  const dsaKeygenResults = {
    "ML-DSA44": benchmark(() => ml_dsa.ml_dsa44.keygen(), 20),
    "ML-DSA65": benchmark(() => ml_dsa.ml_dsa65.keygen(), 20),
    "ML-DSA87": benchmark(() => ml_dsa.ml_dsa87.keygen(), 20)
  };
  formatResults("ML-DSA", "keygen", dsaKeygenResults);
  
  // Pre-generate keys and messages for sign/verify benchmarks
  const dsa44Keys = ml_dsa.ml_dsa44.keygen();
  const dsa65Keys = ml_dsa.ml_dsa65.keygen();
  const dsa87Keys = ml_dsa.ml_dsa87.keygen();
  
  const testMessage = utils.utf8ToBytes('Benchmark test message for ML-DSA signatures');
  
  // Sign
  const dsaSignResults = {
    "ML-DSA44": benchmark(() => ml_dsa.ml_dsa44.sign(dsa44Keys.secretKey, testMessage), 10),
    "ML-DSA65": benchmark(() => ml_dsa.ml_dsa65.sign(dsa65Keys.secretKey, testMessage), 10),
    "ML-DSA87": benchmark(() => ml_dsa.ml_dsa87.sign(dsa87Keys.secretKey, testMessage), 10)
  };
  formatResults("ML-DSA", "sign", dsaSignResults);
  
  // Generate signatures for verify benchmarks
  const dsa44Signature = ml_dsa.ml_dsa44.sign(dsa44Keys.secretKey, testMessage);
  const dsa65Signature = ml_dsa.ml_dsa65.sign(dsa65Keys.secretKey, testMessage);
  const dsa87Signature = ml_dsa.ml_dsa87.sign(dsa87Keys.secretKey, testMessage);
  
  // Verify
  const dsaVerifyResults = {
    "ML-DSA44": benchmark(() => ml_dsa.ml_dsa44.verify(dsa44Keys.publicKey, testMessage, dsa44Signature), 20),
    "ML-DSA65": benchmark(() => ml_dsa.ml_dsa65.verify(dsa65Keys.publicKey, testMessage, dsa65Signature), 20),
    "ML-DSA87": benchmark(() => ml_dsa.ml_dsa87.verify(dsa87Keys.publicKey, testMessage, dsa87Signature), 20)
  };
  formatResults("ML-DSA", "verify", dsaVerifyResults);
  
  // ----------------- SLH-DSA Benchmarks -----------------
  console.log("\nSLH-DSA");
  
  // Define all SLH-DSA variants
  const slhDSAVariants = {
    // SHA2 variants
    "SLH-DSA-SHA2-128F": slh_dsa.slh_dsa_sha2_128f,
    "SLH-DSA-SHA2-128S": slh_dsa.slh_dsa_sha2_128s,
    "SLH-DSA-SHA2-192F": slh_dsa.slh_dsa_sha2_192f,
    "SLH-DSA-SHA2-192S": slh_dsa.slh_dsa_sha2_192s,
    "SLH-DSA-SHA2-256F": slh_dsa.slh_dsa_sha2_256f,
    "SLH-DSA-SHA2-256S": slh_dsa.slh_dsa_sha2_256s,
    // SHAKE variants
    "SLH-DSA-SHAKE-128F": slh_dsa.slh_dsa_shake_128f,
    "SLH-DSA-SHAKE-128S": slh_dsa.slh_dsa_shake_128s,
    "SLH-DSA-SHAKE-192F": slh_dsa.slh_dsa_shake_192f,
    "SLH-DSA-SHAKE-192S": slh_dsa.slh_dsa_shake_192s,
    "SLH-DSA-SHAKE-256F": slh_dsa.slh_dsa_shake_256f,
    "SLH-DSA-SHAKE-256S": slh_dsa.slh_dsa_shake_256s
  };
  
  // Keygen
  console.log("\nRunning SLH-DSA Key Generation benchmarks...");
  const slhDSAKeygenResults = {};
  const slhDSAKeys = {};
  
  // Generate keys for all variants (with lower iterations due to likely higher complexity)
  for (const [name, variant] of Object.entries(slhDSAVariants)) {
    process.stdout.write(`  Testing ${name} keygen... `);
    slhDSAKeygenResults[name] = benchmark(() => variant.keygen(), 5);
    slhDSAKeys[name] = variant.keygen();
    console.log(`✓ (${slhDSAKeygenResults[name].opsPerSec} ops/sec)`);
  }
  console.log("\nKey Generation Results:");
  formatResults("SLH-DSA", "keygen", slhDSAKeygenResults);
  
  // Create test message
  const slhDSATestMessage = utils.utf8ToBytes('Benchmark test message for SLH-DSA signatures');
  
  // Sign
  console.log("\nRunning SLH-DSA Signing benchmarks...");
  const slhDSASignResults = {};
  const slhDSASignatures = {};
  
  // Sign with all variants (with lower iterations due to likely higher complexity)
  for (const [name, variant] of Object.entries(slhDSAVariants)) {
    process.stdout.write(`  Testing ${name} signing... `);
    slhDSASignResults[name] = benchmark(() => variant.sign(slhDSAKeys[name].secretKey, slhDSATestMessage), 3);
    slhDSASignatures[name] = variant.sign(slhDSAKeys[name].secretKey, slhDSATestMessage);
    console.log(`✓ (${slhDSASignResults[name].opsPerSec} ops/sec)`);
  }
  console.log("\nSigning Results:");
  formatResults("SLH-DSA", "sign", slhDSASignResults);
  
  // Verify
  console.log("\nRunning SLH-DSA Verification benchmarks...");
  const slhDSAVerifyResults = {};
  
  // Verify with all variants
  for (const [name, variant] of Object.entries(slhDSAVariants)) {
    process.stdout.write(`  Testing ${name} verification... `);
    slhDSAVerifyResults[name] = benchmark(() => variant.verify(slhDSAKeys[name].publicKey, slhDSATestMessage, slhDSASignatures[name]), 5);
    console.log(`✓ (${slhDSAVerifyResults[name].opsPerSec} ops/sec)`);
  }
  console.log("\nVerification Results:");
  formatResults("SLH-DSA", "verify", slhDSAVerifyResults);
}

// Run the benchmarks
runBenchmarks().catch(err => {
  console.error("Benchmark error:", err);
}); 