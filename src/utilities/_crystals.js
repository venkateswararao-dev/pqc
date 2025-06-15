/**
 * Internal methods for lattice-based ML-KEM and ML-DSA.
 */
import { shake128, shake256 } from '@noble/hashes/sha3';
import { getMask } from "./utils.js";
// TODO: benchmark
function bitReversal(n, bits = 8) {
    const padded = n.toString(2).padStart(8, '0');
    const sliced = padded.slice(-bits).padStart(7, '0');
    const revrsd = sliced.split('').reverse().join('');
    return Number.parseInt(revrsd, 2);
}
export const genCrystals = (opts) => {
    // isKyber: true means Kyber, false means Dilithium
    const { newPoly, N, Q, F, ROOT_OF_UNITY, brvBits, isKyber } = opts;
    const mod = (a, modulo = Q) => {
        const result = a % modulo | 0;
        return (result >= 0 ? result | 0 : (modulo + result) | 0) | 0;
    };
    // -(Q-1)/2 < a <= (Q-1)/2
    const smod = (a, modulo = Q) => {
        const r = mod(a, modulo) | 0;
        return (r > modulo >> 1 ? (r - modulo) | 0 : r) | 0;
    };
    // Generate zettas
    function getZettas() {
        const out = newPoly(N);
        for (let i = 0; i < N; i++) {
            const b = bitReversal(i, brvBits);
            const p = BigInt(ROOT_OF_UNITY) ** BigInt(b) % BigInt(Q);
            out[i] = Number(p) | 0;
        }
        return out;
    }
    const nttZetas = getZettas();
    // Number-Theoretic Transform
    // Explained: https://electricdusk.com/ntt.html
    // Kyber has slightly different params, since there is no 512th primitive root of unity mod q,
    // only 256th primitive root of unity mod. Which also complicates MultiplyNTT.
    // TODO: there should be less ugly way to define this.
    const LEN1 = isKyber ? 128 : N;
    const LEN2 = isKyber ? 1 : 0;
    const NTT = {
        encode: (r) => {
            for (let k = 1, len = 128; len > LEN2; len >>= 1) {
                for (let start = 0; start < N; start += 2 * len) {
                    const zeta = nttZetas[k++];
                    for (let j = start; j < start + len; j++) {
                        const t = mod(zeta * r[j + len]);
                        r[j + len] = mod(r[j] - t) | 0;
                        r[j] = mod(r[j] + t) | 0;
                    }
                }
            }
            return r;
        },
        decode: (r) => {
            for (let k = LEN1 - 1, len = 1 + LEN2; len < LEN1 + LEN2; len <<= 1) {
                for (let start = 0; start < N; start += 2 * len) {
                    const zeta = nttZetas[k--];
                    for (let j = start; j < start + len; j++) {
                        const t = r[j];
                        r[j] = mod(t + r[j + len]);
                        r[j + len] = mod(zeta * (r[j + len] - t));
                    }
                }
            }
            for (let i = 0; i < r.length; i++)
                r[i] = mod(F * r[i]);
            return r;
        },
    };
    // Encode polynominal as bits
    const bitsCoder = (d, c) => {
        const mask = getMask(d);
        const bytesLen = d * (N / 8);
        return {
            bytesLen,
            encode: (poly) => {
                const r = new Uint8Array(bytesLen);
                for (let i = 0, buf = 0, bufLen = 0, pos = 0; i < poly.length; i++) {
                    buf |= (c.encode(poly[i]) & mask) << bufLen;
                    bufLen += d;
                    for (; bufLen >= 8; bufLen -= 8, buf >>= 8)
                        r[pos++] = buf & getMask(bufLen);
                }
                return r;
            },
            decode: (bytes) => {
                const r = newPoly(N);
                for (let i = 0, buf = 0, bufLen = 0, pos = 0; i < bytes.length; i++) {
                    buf |= bytes[i] << bufLen;
                    bufLen += 8;
                    for (; bufLen >= d; bufLen -= d, buf >>= d)
                        r[pos++] = c.decode(buf & mask);
                }
                return r;
            },
        };
    };
    return { mod, smod, nttZetas, NTT, bitsCoder };
};
const createXofShake = (shake) => (seed, blockLen) => {
    if (!blockLen)
        blockLen = shake.blockLen;
    // Optimizations that won't mater:
    // - cached seed update (two .update(), on start and on the end)
    // - another cache which cloned into working copy
    // Faster than multiple updates, since seed less than blockLen
    const _seed = new Uint8Array(seed.length + 2);
    _seed.set(seed);
    const seedLen = seed.length;
    const buf = new Uint8Array(blockLen); // == shake128.blockLen
    let h = shake.create({});
    let calls = 0;
    let xofs = 0;
    return {
        stats: () => ({ calls, xofs }),
        get: (x, y) => {
            _seed[seedLen + 0] = x;
            _seed[seedLen + 1] = y;
            h.destroy();
            h = shake.create({}).update(_seed);
            calls++;
            return () => {
                xofs++;
                return h.xofInto(buf);
            };
        },
        clean: () => {
            h.destroy();
            buf.fill(0);
            _seed.fill(0);
        },
    };
};
export const XOF128 = /* @__PURE__ */ createXofShake(shake128);
export const XOF256 = /* @__PURE__ */ createXofShake(shake256);