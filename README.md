# pqc

`pqc` is an open-source NPM package providing implementations of post-quantum cryptographic algorithms based on NIST standards. It includes modules for quantum-resistant Key Encapsulation Mechanisms (KEM) and Digital Signature Algorithms (DSA).

## Features

- **ML-KEM** (Module-Lattice Key Encapsulation Mechanism)
- **ML-DSA** (Module-Lattice Digital Signature Algorithm)
- **SLH-DSA** (Stateless Hash-based Digital Signature Algorithm)
- Fully compliant with NIST standards: FIPS 203, FIPS 204, and FIPS 205

## Installation

To install the package, run:

```bash
npm install pqc
```

## Usage

Here's how to use the package with examples for each of the provided algorithms.

### ML-KEM (Key Encapsulation Mechanism)

In this example, Alice and Bob generate and share a secret key using ML-KEM-768:

```javascript
import { ml_kem, ml_dsa, slh_dsa, utils } from 'pqc';

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
```

### ML-DSA (Digital Signature Algorithm)

In this example, Alice signs a message and Bob verifies it using ML-DSA-65:

```javascript
// 1. [Alice] generates a key pair
const keys = ml_dsa.ml_dsa65.keygen();

// 2. [Alice] signs the message
const msg = utils.utf8ToBytes('Post Quantum Cryptography');
const sig = ml_dsa.ml_dsa65.sign(keys.secretKey, msg);

// 3. [Bob] verifies the message signature
const isValid = ml_dsa.ml_dsa65.verify(keys.publicKey, msg, sig);
console.log('Signature valid:', isValid);
```

### SLH-DSA (Stateless Hash-based Digital Signature Algorithm)

In this example, Alice uses SLH-DSA to generate a signature and verify it:

```javascript
// 1. [Alice] generates a key pair using SLH-DSA-128f
const sph = slh_dsa.slh_dsa_sha2_128f;
const keys2 = sph.keygen();

// 2. [Alice] signs the message
const msg2 = utils.utf8ToBytes('Post Quantum Cryptography');
const sig2 = sph.sign(keys2.secretKey, msg2);

// 3. [Bob] verifies the signature
const isValid2 = sph.verify(keys2.publicKey, msg2, sig2);
console.log('Signature valid for SLH-DSA:', isValid2);
```

## API Documentation

### ML-KEM
- `ml_kem.ml_kem512`: 128-bit security level
- `ml_kem.ml_kem768`: 192-bit security level
- `ml_kem.ml_kem1024`: 256-bit security level

### ML-DSA
- `ml_dsa.ml_dsa44`: 128-bit security level
- `ml_dsa.ml_dsa65`: 192-bit security level
- `ml_dsa.ml_dsa87`: 256-bit security level

### SLH-DSA

#### SHA2 Variants
- `slh_dsa.slh_dsa_sha2_128f`: 128-bit fast SHA2
- `slh_dsa.slh_dsa_sha2_128s`: 128-bit small SHA2
- `slh_dsa.slh_dsa_sha2_192f`: 192-bit fast SHA2
- `slh_dsa.slh_dsa_sha2_192s`: 192-bit small SHA2
- `slh_dsa.slh_dsa_sha2_256f`: 256-bit fast SHA2
- `slh_dsa.slh_dsa_sha2_256s`: 256-bit small SHA2

#### SHAKE Variants
- `slh_dsa.slh_dsa_shake_128f`: 128-bit fast SHAKE
- `slh_dsa.slh_dsa_shake_128s`: 128-bit small SHAKE
- `slh_dsa.slh_dsa_shake_192f`: 192-bit fast SHAKE
- `slh_dsa.slh_dsa_shake_192s`: 192-bit small SHAKE
- `slh_dsa.slh_dsa_shake_256f`: 256-bit fast SHAKE
- `slh_dsa.slh_dsa_shake_256s`: 256-bit small SHAKE

## Testing

The package includes a comprehensive test suite that verifies all algorithms and utility functions. To run the tests:

```bash
node node_modules/pqc/test.js
```

This will run tests for:
- All ML-KEM variants (512, 768, 1024)
- All ML-DSA variants (44, 65, 87)
- All SLH-DSA SHA2 variants (128f/s, 192f/s, 256f/s)
- All SLH-DSA SHAKE variants (128f/s, 192f/s, 256f/s)
- Utility functions (UTF-8 conversion, byte equality, random byte generation)

## Performance Benchmarks

The package includes benchmarking tools to measure the performance of each algorithm. To run the benchmarks:

```bash
node node_modules/pqc/benchmark.js
```

The benchmark will measure:

### ML-KEM Performance
- Key generation speed for all security levels
- Encapsulation (encryption) performance
- Decapsulation (decryption) performance

### ML-DSA Performance
- Key generation speed for all security levels
- Signing performance
- Verification performance

### SLH-DSA Performance
- Key generation for all SHA2 and SHAKE variants
- Signing performance across all variants
- Verification performance across all variants

Benchmark results will show operations per second and microseconds per operation for each algorithm.
