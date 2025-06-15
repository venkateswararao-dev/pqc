import { ml_kem, ml_dsa, slh_dsa, utils } from "./index.js";

console.log("=== Testing ML-KEM (Key Encapsulation) ===");

// Test ML-KEM 512
console.log("\nTesting ML-KEM 512:");
const kem512AliceKeys = ml_kem.ml_kem512.keygen();
const { cipherText: kem512CipherText, sharedSecret: kem512BobShared } = ml_kem.ml_kem512.encapsulate(kem512AliceKeys.publicKey);
const kem512AliceShared = ml_kem.ml_kem512.decapsulate(kem512CipherText, kem512AliceKeys.secretKey);
console.log("Keys match:", utils.equalBytes(kem512AliceShared, kem512BobShared));

// Test ML-KEM 768
console.log("\nTesting ML-KEM 768:");
const kem768AliceKeys = ml_kem.ml_kem768.keygen();
const { cipherText: kem768CipherText, sharedSecret: kem768BobShared } = ml_kem.ml_kem768.encapsulate(kem768AliceKeys.publicKey);
const kem768AliceShared = ml_kem.ml_kem768.decapsulate(kem768CipherText, kem768AliceKeys.secretKey);
console.log("Keys match:", utils.equalBytes(kem768AliceShared, kem768BobShared));

// Test ML-KEM 1024
console.log("\nTesting ML-KEM 1024:");
const kem1024AliceKeys = ml_kem.ml_kem1024.keygen();
const { cipherText: kem1024CipherText, sharedSecret: kem1024BobShared } = ml_kem.ml_kem1024.encapsulate(kem1024AliceKeys.publicKey);
const kem1024AliceShared = ml_kem.ml_kem1024.decapsulate(kem1024CipherText, kem1024AliceKeys.secretKey);
console.log("Keys match:", utils.equalBytes(kem1024AliceShared, kem1024BobShared));

console.log("\n=== Testing ML-DSA (Digital Signatures) ===");

// Test ML-DSA 44 (previously called ml_dsa2)
console.log("\nTesting ML-DSA 44:");
const dsa44Keys = ml_dsa.ml_dsa44.keygen();
const dsa44Msg = utils.utf8ToBytes('Testing ML-DSA 44 Signature');
const dsa44Sig = ml_dsa.ml_dsa44.sign(dsa44Keys.secretKey, dsa44Msg);
const dsa44IsValid = ml_dsa.ml_dsa44.verify(dsa44Keys.publicKey, dsa44Msg, dsa44Sig);
console.log("Signature valid:", dsa44IsValid);

// Test ML-DSA 65 (previously called ml_dsa3)
console.log("\nTesting ML-DSA 65:");
const dsa65Keys = ml_dsa.ml_dsa65.keygen();
const dsa65Msg = utils.utf8ToBytes('Testing ML-DSA 65 Signature');
const dsa65Sig = ml_dsa.ml_dsa65.sign(dsa65Keys.secretKey, dsa65Msg);
const dsa65IsValid = ml_dsa.ml_dsa65.verify(dsa65Keys.publicKey, dsa65Msg, dsa65Sig);
console.log("Signature valid:", dsa65IsValid);

// Test ML-DSA 87 (previously called ml_dsa5)
console.log("\nTesting ML-DSA 87:");
const dsa87Keys = ml_dsa.ml_dsa87.keygen();
const dsa87Msg = utils.utf8ToBytes('Testing ML-DSA 87 Signature');
const dsa87Sig = ml_dsa.ml_dsa87.sign(dsa87Keys.secretKey, dsa87Msg);
const dsa87IsValid = ml_dsa.ml_dsa87.verify(dsa87Keys.publicKey, dsa87Msg, dsa87Sig);
console.log("Signature valid:", dsa87IsValid);

console.log("\n=== Testing SLH-DSA (Stateless Hash-based Signatures) ===");

// Test SLH-DSA SHA2 variants
console.log("\nTesting SLH-DSA SHA2 variants:");

// 128f
const sha2_128f = slh_dsa.slh_dsa_sha2_128f;
const sha2_128f_keys = sha2_128f.keygen();
const sha2_128f_msg = utils.utf8ToBytes('Testing SLH-DSA SHA2-128F');
const sha2_128f_sig = sha2_128f.sign(sha2_128f_keys.secretKey, sha2_128f_msg);
const sha2_128f_valid = sha2_128f.verify(sha2_128f_keys.publicKey, sha2_128f_msg, sha2_128f_sig);
console.log("SHA2-128F valid:", sha2_128f_valid);

// 128s
const sha2_128s = slh_dsa.slh_dsa_sha2_128s;
const sha2_128s_keys = sha2_128s.keygen();
const sha2_128s_msg = utils.utf8ToBytes('Testing SLH-DSA SHA2-128S');
const sha2_128s_sig = sha2_128s.sign(sha2_128s_keys.secretKey, sha2_128s_msg);
const sha2_128s_valid = sha2_128s.verify(sha2_128s_keys.publicKey, sha2_128s_msg, sha2_128s_sig);
console.log("SHA2-128S valid:", sha2_128s_valid);

// 192f
const sha2_192f = slh_dsa.slh_dsa_sha2_192f;
const sha2_192f_keys = sha2_192f.keygen();
const sha2_192f_msg = utils.utf8ToBytes('Testing SLH-DSA SHA2-192F');
const sha2_192f_sig = sha2_192f.sign(sha2_192f_keys.secretKey, sha2_192f_msg);
const sha2_192f_valid = sha2_192f.verify(sha2_192f_keys.publicKey, sha2_192f_msg, sha2_192f_sig);
console.log("SHA2-192F valid:", sha2_192f_valid);

// 192s
const sha2_192s = slh_dsa.slh_dsa_sha2_192s;
const sha2_192s_keys = sha2_192s.keygen();
const sha2_192s_msg = utils.utf8ToBytes('Testing SLH-DSA SHA2-192S');
const sha2_192s_sig = sha2_192s.sign(sha2_192s_keys.secretKey, sha2_192s_msg);
const sha2_192s_valid = sha2_192s.verify(sha2_192s_keys.publicKey, sha2_192s_msg, sha2_192s_sig);
console.log("SHA2-192S valid:", sha2_192s_valid);

// 256f
const sha2_256f = slh_dsa.slh_dsa_sha2_256f;
const sha2_256f_keys = sha2_256f.keygen();
const sha2_256f_msg = utils.utf8ToBytes('Testing SLH-DSA SHA2-256F');
const sha2_256f_sig = sha2_256f.sign(sha2_256f_keys.secretKey, sha2_256f_msg);
const sha2_256f_valid = sha2_256f.verify(sha2_256f_keys.publicKey, sha2_256f_msg, sha2_256f_sig);
console.log("SHA2-256F valid:", sha2_256f_valid);

// 256s
const sha2_256s = slh_dsa.slh_dsa_sha2_256s;
const sha2_256s_keys = sha2_256s.keygen();
const sha2_256s_msg = utils.utf8ToBytes('Testing SLH-DSA SHA2-256S');
const sha2_256s_sig = sha2_256s.sign(sha2_256s_keys.secretKey, sha2_256s_msg);
const sha2_256s_valid = sha2_256s.verify(sha2_256s_keys.publicKey, sha2_256s_msg, sha2_256s_sig);
console.log("SHA2-256S valid:", sha2_256s_valid);

// Test SLH-DSA SHAKE variants
console.log("\nTesting SLH-DSA SHAKE variants:");

// 128f
const shake_128f = slh_dsa.slh_dsa_shake_128f;
const shake_128f_keys = shake_128f.keygen();
const shake_128f_msg = utils.utf8ToBytes('Testing SLH-DSA SHAKE-128F');
const shake_128f_sig = shake_128f.sign(shake_128f_keys.secretKey, shake_128f_msg);
const shake_128f_valid = shake_128f.verify(shake_128f_keys.publicKey, shake_128f_msg, shake_128f_sig);
console.log("SHAKE-128F valid:", shake_128f_valid);

// 128s
const shake_128s = slh_dsa.slh_dsa_shake_128s;
const shake_128s_keys = shake_128s.keygen();
const shake_128s_msg = utils.utf8ToBytes('Testing SLH-DSA SHAKE-128S');
const shake_128s_sig = shake_128s.sign(shake_128s_keys.secretKey, shake_128s_msg);
const shake_128s_valid = shake_128s.verify(shake_128s_keys.publicKey, shake_128s_msg, shake_128s_sig);
console.log("SHAKE-128S valid:", shake_128s_valid);

// 192f
const shake_192f = slh_dsa.slh_dsa_shake_192f;
const shake_192f_keys = shake_192f.keygen();
const shake_192f_msg = utils.utf8ToBytes('Testing SLH-DSA SHAKE-192F');
const shake_192f_sig = shake_192f.sign(shake_192f_keys.secretKey, shake_192f_msg);
const shake_192f_valid = shake_192f.verify(shake_192f_keys.publicKey, shake_192f_msg, shake_192f_sig);
console.log("SHAKE-192F valid:", shake_192f_valid);

// 192s
const shake_192s = slh_dsa.slh_dsa_shake_192s;
const shake_192s_keys = shake_192s.keygen();
const shake_192s_msg = utils.utf8ToBytes('Testing SLH-DSA SHAKE-192S');
const shake_192s_sig = shake_192s.sign(shake_192s_keys.secretKey, shake_192s_msg);
const shake_192s_valid = shake_192s.verify(shake_192s_keys.publicKey, shake_192s_msg, shake_192s_sig);
console.log("SHAKE-192S valid:", shake_192s_valid);

// 256f
const shake_256f = slh_dsa.slh_dsa_shake_256f;
const shake_256f_keys = shake_256f.keygen();
const shake_256f_msg = utils.utf8ToBytes('Testing SLH-DSA SHAKE-256F');
const shake_256f_sig = shake_256f.sign(shake_256f_keys.secretKey, shake_256f_msg);
const shake_256f_valid = shake_256f.verify(shake_256f_keys.publicKey, shake_256f_msg, shake_256f_sig);
console.log("SHAKE-256F valid:", shake_256f_valid);

// 256s
const shake_256s = slh_dsa.slh_dsa_shake_256s;
const shake_256s_keys = shake_256s.keygen();
const shake_256s_msg = utils.utf8ToBytes('Testing SLH-DSA SHAKE-256S');
const shake_256s_sig = shake_256s.sign(shake_256s_keys.secretKey, shake_256s_msg);
const shake_256s_valid = shake_256s.verify(shake_256s_keys.publicKey, shake_256s_msg, shake_256s_sig);
console.log("SHAKE-256S valid:", shake_256s_valid);

// Test utility functions
console.log("\n=== Testing Utility Functions ===");

// Test UTF8 conversion
const testStr = "Testing UTF8 conversion";
const testBytes = utils.utf8ToBytes(testStr);
console.log("UTF8 to bytes:", testBytes);

// Test bytes equality
const bytesA = utils.utf8ToBytes("Same string");
const bytesB = utils.utf8ToBytes("Same string");
const bytesC = utils.utf8ToBytes("Different string");
console.log("Equal bytes test (true):", utils.equalBytes(bytesA, bytesB));
console.log("Equal bytes test (false):", utils.equalBytes(bytesA, bytesC));

// Test random bytes generation
const randomTest = utils.randomBytes(16);
console.log("Random bytes generation:", randomTest);