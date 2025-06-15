/**
 * Utilities for hex, bytearray and number handling.
 */
import { abytes } from '@noble/hashes/_assert';
import { sha224, sha256 } from '@noble/hashes/sha256';
import { sha3_224, sha3_256, sha3_384, sha3_512, shake128, shake256 } from '@noble/hashes/sha3';
import { sha384, sha512, sha512_224, sha512_256 } from '@noble/hashes/sha512';
import { concatBytes, hexToBytes, randomBytes as randb, utf8ToBytes, } from '@noble/hashes/utils';
export const ensureBytes = abytes;
export const randomBytes = randb;
export { concatBytes, utf8ToBytes };
// Compares 2 u8a-s in kinda constant time
export function equalBytes(a, b) {
    if (a.length !== b.length)
        return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++)
        diff |= a[i] ^ b[i];
    return diff === 0;
}
export function splitCoder(...lengths) {
    const getLength = (c) => (typeof c === 'number' ? c : c.bytesLen);
    const bytesLen = lengths.reduce((sum, a) => sum + getLength(a), 0);
    return {
        bytesLen,
        encode: (bufs) => {
            const res = new Uint8Array(bytesLen);
            for (let i = 0, pos = 0; i < lengths.length; i++) {
                const c = lengths[i];
                const l = getLength(c);
                const b = typeof c === 'number' ? bufs[i] : c.encode(bufs[i]);
                ensureBytes(b, l);
                res.set(b, pos);
                if (typeof c !== 'number')
                    b.fill(0); // clean
                pos += l;
            }
            return res;
        },
        decode: (buf) => {
            ensureBytes(buf, bytesLen);
            const res = [];
            for (const c of lengths) {
                const l = getLength(c);
                const b = buf.subarray(0, l);
                res.push(typeof c === 'number' ? b : c.decode(b));
                buf = buf.subarray(l);
            }
            return res;
        },
    };
}
// nano-packed.array (fixed size)
export function vecCoder(c, vecLen) {
    const bytesLen = vecLen * c.bytesLen;
    return {
        bytesLen,
        encode: (u) => {
            if (u.length !== vecLen)
                throw new Error(`vecCoder.encode: wrong length=${u.length}. Expected: ${vecLen}`);
            const res = new Uint8Array(bytesLen);
            for (let i = 0, pos = 0; i < u.length; i++) {
                const b = c.encode(u[i]);
                res.set(b, pos);
                b.fill(0); // clean
                pos += b.length;
            }
            return res;
        },
        decode: (a) => {
            ensureBytes(a, bytesLen);
            const r = [];
            for (let i = 0; i < a.length; i += c.bytesLen)
                r.push(c.decode(a.subarray(i, i + c.bytesLen)));
            return r;
        },
    };
}
// cleanBytes(new Uint8Array(), [new Uint16Array(), new Uint32Array()])
export function cleanBytes(...list) {
    for (const t of list) {
        if (Array.isArray(t))
            for (const b of t)
                b.fill(0);
        else
            t.fill(0);
    }
}
export function getMask(bits) {
    return (1 << bits) - 1; // 4 -> 0b1111
}
export const EMPTY = new Uint8Array(0);
export function getMessage(msg, ctx = EMPTY) {
    ensureBytes(msg);
    ensureBytes(ctx);
    if (ctx.length > 255)
        throw new Error('context should be less than 255 bytes');
    return concatBytes(new Uint8Array([0, ctx.length]), ctx, msg);
}
// OIDS from https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
// TODO: maybe add 'OID' property to hashes themselves to improve tree-shaking?
const HASHES = {
    'SHA2-256': { oid: hexToBytes('0609608648016503040201'), hash: sha256 },
    'SHA2-384': { oid: hexToBytes('0609608648016503040202'), hash: sha384 },
    'SHA2-512': { oid: hexToBytes('0609608648016503040203'), hash: sha512 },
    'SHA2-224': { oid: hexToBytes('0609608648016503040204'), hash: sha224 },
    'SHA2-512/224': { oid: hexToBytes('0609608648016503040205'), hash: sha512_224 },
    'SHA2-512/256': { oid: hexToBytes('0609608648016503040206'), hash: sha512_256 },
    'SHA3-224': { oid: hexToBytes('0609608648016503040207'), hash: sha3_224 },
    'SHA3-256': { oid: hexToBytes('0609608648016503040208'), hash: sha3_256 },
    'SHA3-384': { oid: hexToBytes('0609608648016503040209'), hash: sha3_384 },
    'SHA3-512': { oid: hexToBytes('060960864801650304020A'), hash: sha3_512 },
    'SHAKE-128': {
        oid: hexToBytes('060960864801650304020B'),
        hash: (msg) => shake128(msg, { dkLen: 32 }),
    },
    'SHAKE-256': {
        oid: hexToBytes('060960864801650304020C'),
        hash: (msg) => shake256(msg, { dkLen: 64 }),
    },
};
export function getMessagePrehash(hashName, msg, ctx = EMPTY) {
    ensureBytes(msg);
    ensureBytes(ctx);
    if (ctx.length > 255)
        throw new Error('context should be less than 255 bytes');
    if (!HASHES[hashName])
        throw new Error('unknown hash: ' + hashName);
    const { oid, hash } = HASHES[hashName];
    const hashed = hash(msg);
    return concatBytes(new Uint8Array([1, ctx.length]), ctx, oid, hashed);
}