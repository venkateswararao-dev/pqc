import { ml_kem, ml_dsa, slh_dsa, utils } from './index.js';

// 1. [Alice] generates a key pair
const aliceKeys = ml_kem.ml_kem768.keygen();

// 2. [Bob] generates a shared secret for Alice's public key
// bobShared never leaves [Bob] system and is unknown to other parties
const { cipherText, sharedSecret: bobShared } = ml_kem.ml_kem768.encapsulate(aliceKeys.publicKey);

// 3. [Alice] gets and decrypts cipherText from Bob
const aliceShared = ml_kem.ml_kem768.decapsulate(cipherText, aliceKeys.secretKey);

// Now, both Alice and Bob have the same sharedSecret key
// without exchanging it in plain text: aliceShared == bobShared
console.log('Alice shared secret:', aliceShared);
console.log('Bob shared secret:', bobShared);

// 1. [Alice] generates a key pair
const keys = ml_dsa.ml_dsa65.keygen();

// 2. [Alice] signs the message
const msg = utils.utf8ToBytes('Post Quantum Cryptography');
const sig = ml_dsa.ml_dsa65.sign(keys.secretKey, msg);

// 3. [Bob] verifies the message signature
const isValid = ml_dsa.ml_dsa65.verify(keys.publicKey, msg, sig);
console.log('Signature valid:', isValid);

// 1. [Alice] generates a key pair using SLH-DSA-128f
const sph = slh_dsa.slh_dsa_sha2_128f;
const keys2 = sph.keygen();

// 2. [Alice] signs the message
const msg2 = utils.utf8ToBytes('Post Quantum Cryptography');
const sig2 = sph.sign(keys2.secretKey, msg2);

// 3. [Bob] verifies the signature
const isValid2 = sph.verify(keys2.publicKey, msg2, sig2);
console.log('Signature valid for SLH-DSA:', isValid2);