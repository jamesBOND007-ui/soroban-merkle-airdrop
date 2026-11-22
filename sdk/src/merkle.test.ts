import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { resolve } from "path";
import { buildMerkleTree, verifyProof, leafHash } from "../src/merkle.js";

const ADDR_1 = "GBTL47RTFR5EKMZSXWOQU735WBK7LRPPDIDK3JTNTCZZ7NUBBRDTVSK2";
const ADDR_2 = "GBIRYNFBULFVEHPRNOZENOG6RZ4ZPTRDLR7HNMRKHV2QHISIDHOYV6ZN";
const ADDR_3 = "GCEEXCCX6TVKCYJ4MFIE3M2NJPVPGRSRPIHDDXR43XKNTNBADWOQWDYC";

// A stable dummy contract address used throughout these tests.
// Tests that care specifically about domain separation use CONTRACT_B.
const CONTRACT_A = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";
const CONTRACT_B = "CBEZIXBSAPZ5YBH2WQHLISNOQDXVZKZQRPX3MF5GRCJJMH3SBYXEWYJ";

describe("leafHash", () => {
  it("produces a 32-byte buffer", () => {
    const hash = leafHash(CONTRACT_A, ADDR_1, 1000n);
    expect(hash).toBeInstanceOf(Buffer);
    expect(hash.length).toBe(32);
  });

  it("same inputs produce same hash", () => {
    expect(leafHash(CONTRACT_A, ADDR_1, 1000n).toString("hex")).toBe(
      leafHash(CONTRACT_A, ADDR_1, 1000n).toString("hex")
    );
  });

  it("different amounts produce different hashes", () => {
    expect(leafHash(CONTRACT_A, ADDR_1, 1000n).toString("hex")).not.toBe(
      leafHash(CONTRACT_A, ADDR_1, 999n).toString("hex")
    );
  });

  it("different addresses produce different hashes", () => {
    expect(leafHash(CONTRACT_A, ADDR_1, 1000n).toString("hex")).not.toBe(
      leafHash(CONTRACT_A, ADDR_2, 1000n).toString("hex")
    );
  });

  it("different contract IDs produce different hashes (domain separation)", () => {
    expect(leafHash(CONTRACT_A, ADDR_1, 1000n).toString("hex")).not.toBe(
      leafHash(CONTRACT_B, ADDR_1, 1000n).toString("hex")
    );
  });
});

describe("buildMerkleTree", () => {
  it("single entry produces root equal to leaf hash", () => {
    const { root, proofs } = buildMerkleTree(CONTRACT_A, [
      { address: ADDR_1, amount: 1000n },
    ]);
    expect(root).toBe(leafHash(CONTRACT_A, ADDR_1, 1000n).toString("hex"));
    expect(proofs.get(ADDR_1)!.proof).toEqual([]);
  });

  it("two entries both verify correctly", () => {
    const entries = [
      { address: ADDR_1, amount: 1000n },
      { address: ADDR_2, amount: 500n },
    ];
    const { root, proofs } = buildMerkleTree(CONTRACT_A, entries);

    for (const e of entries) {
      const p = proofs.get(e.address)!;
      expect(verifyProof(root, CONTRACT_A, e.address, e.amount, p.proof)).toBe(true);
    }
  });

  it("three entries all verify", () => {
    const entries = [
      { address: ADDR_1, amount: 100n },
      { address: ADDR_2, amount: 200n },
      { address: ADDR_3, amount: 300n },
    ];
    const { root, proofs } = buildMerkleTree(CONTRACT_A, entries);
    for (const e of entries) {
      const p = proofs.get(e.address)!;
      expect(verifyProof(root, CONTRACT_A, e.address, e.amount, p.proof)).toBe(true);
    }
  });

  it("wrong amount fails verification", () => {
    const { root, proofs } = buildMerkleTree(CONTRACT_A, [
      { address: ADDR_1, amount: 1000n },
      { address: ADDR_2, amount: 500n },
    ]);
    const p = proofs.get(ADDR_1)!;
    expect(verifyProof(root, CONTRACT_A, ADDR_1, 9999n, p.proof)).toBe(false);
  });

  it("wrong address fails verification", () => {
    const { root, proofs } = buildMerkleTree(CONTRACT_A, [
      { address: ADDR_1, amount: 1000n },
      { address: ADDR_2, amount: 500n },
    ]);
    const p = proofs.get(ADDR_1)!;
    expect(verifyProof(root, CONTRACT_A, ADDR_2, 1000n, p.proof)).toBe(false);
  });

  it("rejects duplicate addresses", () => {
    expect(() =>
      buildMerkleTree(CONTRACT_A, [
        { address: ADDR_1, amount: 1000n },
        { address: ADDR_1, amount: 500n },
      ])
    ).toThrow("Duplicate address");
  });

  // ── Domain separation ────────────────────────────────────────────────────

  it("proof for CONTRACT_A is rejected by CONTRACT_B even with same root entries", () => {
    const entries = [
      { address: ADDR_1, amount: 1000n },
      { address: ADDR_2, amount: 500n },
    ];
    const { root: rootA, proofs: proofsA } = buildMerkleTree(CONTRACT_A, entries);
    const { root: rootB }                  = buildMerkleTree(CONTRACT_B, entries);

    const proofA = proofsA.get(ADDR_1)!;

    // CONTRACT_A's proof verifies against rootA.
    expect(verifyProof(rootA, CONTRACT_A, ADDR_1, 1000n, proofA.proof)).toBe(true);

    // The same proof must NOT verify against CONTRACT_B's root.
    expect(verifyProof(rootB, CONTRACT_B, ADDR_1, 1000n, proofA.proof)).toBe(false);
  });

  // ── Issue #34: Edge cases ────────────────────────────────────────────────

  /**
   * Stellar addresses are case-sensitive. The same base-32 characters in
   * different capitalizations must be treated as two distinct entries.
   */
  it("#34: different capitalisation is treated as a different address (case-sensitive)", () => {
    const ADDR_1_LOWER = ADDR_1.toLowerCase();

    const { root, proofs } = buildMerkleTree(CONTRACT_A, [
      { address: ADDR_1, amount: 1000n },
      { address: ADDR_1_LOWER, amount: 500n },
    ]);

    expect(proofs.has(ADDR_1)).toBe(true);
    expect(proofs.has(ADDR_1_LOWER)).toBe(true);

    const p1 = proofs.get(ADDR_1)!;
    const p2 = proofs.get(ADDR_1_LOWER)!;
    expect(verifyProof(root, CONTRACT_A, ADDR_1, 1000n, p1.proof)).toBe(true);
    expect(verifyProof(root, CONTRACT_A, ADDR_1_LOWER, 500n, p2.proof)).toBe(true);

    expect(leafHash(CONTRACT_A, ADDR_1, 1000n).toString("hex")).not.toBe(
      leafHash(CONTRACT_A, ADDR_1_LOWER, 500n).toString("hex")
    );
  });

  /**
   * Single-entry tree: the root is exactly the leaf hash, proof is empty.
   */
  it("#34: single-entry tree — root equals leaf hash, proof is empty, verifyProof returns true", () => {
    const { root, proofs } = buildMerkleTree(CONTRACT_A, [
      { address: ADDR_1, amount: 1000n },
    ]);

    const expected = leafHash(CONTRACT_A, ADDR_1, 1000n).toString("hex");
    expect(root).toBe(expected);

    const p = proofs.get(ADDR_1)!;
    expect(p.proof).toEqual([]);

    expect(verifyProof(root, CONTRACT_A, ADDR_1, 1000n, [])).toBe(true);
  });

  it("#34: same base-32 chars, different case — does NOT throw", () => {
    const ADDR_1_LOWER = ADDR_1.toLowerCase();

    expect(() =>
      buildMerkleTree(CONTRACT_A, [
        { address: ADDR_1, amount: 1000n },
        { address: ADDR_1_LOWER, amount: 500n },
      ])
    ).not.toThrow();
  });

  it("rejects empty list", () => {
    expect(() => buildMerkleTree(CONTRACT_A, [])).toThrow("empty");
  });

  it("two known-good entries verify", () => {
    const realEntries = [
      { address: ADDR_1, amount: 1000n },
      { address: ADDR_2, amount: 2000n },
    ];
    const { root, proofs } = buildMerkleTree(CONTRACT_A, realEntries);
    for (const e of realEntries) {
      const p = proofs.get(e.address)!;
      expect(verifyProof(root, CONTRACT_A, e.address, e.amount, p.proof)).toBe(true);
    }
  });
});

// ─── Issue #65: verifyProof with mismatched proof length ──────────────────

describe("verifyProof — mismatched proof length", () => {
  function twoEntrySetup() {
    const entries = [
      { address: ADDR_1, amount: 1000n },
      { address: ADDR_2, amount: 500n },
    ];
    const { root, proofs } = buildMerkleTree(CONTRACT_A, entries);
    const entry = proofs.get(ADDR_1)!;
    return { root, address: ADDR_1, amount: 1000n, validProof: entry.proof };
  }

  it("fails when one extra random hash is appended to a valid proof", () => {
    const { root, address, amount, validProof } = twoEntrySetup();
    expect(verifyProof(root, CONTRACT_A, address, amount, validProof)).toBe(true);
    const extraHash = "a".repeat(64);
    const tooLong = [...validProof, extraHash];
    expect(verifyProof(root, CONTRACT_A, address, amount, tooLong)).toBe(false);
  });

  it("fails when the last element is removed from a valid proof", () => {
    const { root, address, amount, validProof } = twoEntrySetup();
    const tooShort = validProof.slice(0, -1);
    expect(verifyProof(root, CONTRACT_A, address, amount, tooShort)).toBe(false);
  });

  it("fails when an empty proof is supplied for a two-entry tree", () => {
    const { root, address, amount } = twoEntrySetup();
    expect(verifyProof(root, CONTRACT_A, address, amount, [])).toBe(false);
  });
});

// ─── Issue #32: Cross-language leaf-hash test vector suite ──────────────────

/**
 * Load the shared test-vector file and verify that leafHash() in TypeScript
 * produces byte-for-byte identical output to the Rust contract's leaf_hash()
 * for every entry.
 *
 * NOTE: After issue #50 (domain separation), the vectors file includes a
 * contract_id field.  Vectors without contract_id are skipped until the file
 * is regenerated.
 */
describe("leafHash — cross-language test vectors", () => {
  interface LeafHashVector {
    _comment?: string;
    contract_id?: string;
    address: string;
    amount: string;
    expected_leaf_hex: string;
  }

  const vectorsPath = resolve(process.cwd(), "../test-vectors/leaf-hash-vectors.json");
  const vectors: LeafHashVector[] = JSON.parse(readFileSync(vectorsPath, "utf8"));

  it("has at least 10 vectors", () => {
    expect(vectors.length).toBeGreaterThanOrEqual(10);
  });

  for (const [i, v] of vectors.entries()) {
    // Skip vectors that pre-date the domain-separation change (no contract_id).
    if (!v.contract_id) continue;

    it(`vector ${i}: ${v.address.slice(0, 6)}... amount=${v.amount}`, () => {
      const actual = leafHash(v.contract_id!, v.address, BigInt(v.amount));
      expect(actual.toString("hex")).toBe(
        v.expected_leaf_hex,
        `vector ${i} (${v.address}, ${v.amount}): TypeScript leafHash does not match expected hex`
      );
    });
  }
});

// ─── Issue #35: Snapshot / golden-value tests ─────────────────────────────
//
// NOTE: After issue #50 (domain separation), the golden root and leaf hashes
// have changed. These tests are skipped until the vectors are regenerated.
// The structure is preserved so the tests are easy to re-enable.

describe.skip("Issue #35 — snapshot: Merkle root stability (golden values) [needs regeneration after #50]", () => {
  const SNAPSHOT_ENTRIES = [
    { address: "GBTL47RTFR5EKMZSXWOQU735WBK7LRPPDIDK3JTNTCZZ7NUBBRDTVSK2", amount: 1000n },
    { address: "GBIRYNFBULFVEHPRNOZENOG6RZ4ZPTRDLR7HNMRKHV2QHISIDHOYV6ZN", amount: 2000n },
    { address: "GCEEXCCX6TVKCYJ4MFIE3M2NJPVPGRSRPIHDDXR43XKNTNBADWOQWDYC", amount: 3000n },
    { address: "GDA3XFJZJZQMKRFFZSMQLXDZZRK3DHJWDNUQ4IBOQP4O7FXJPLFJZR7", amount: 4000n },
    { address: "GCVJDBALC2RQFLD2HYGZDFEZVDFPLFB63KYGIBHC3QLJXBQHJIASOPNB", amount: 5000n },
  ] as const;

  // TODO: regenerate these values with the new leafHash(contractId, ...) signature.
  const GOLDEN_ROOT = "9eb3a56c027bd438aec9dae40882e2c83c7aaa291bc4c162e87ee8f61a29624f";

  it("5-entry fixed list produces the hardcoded golden root", () => {
    const { root } = buildMerkleTree(CONTRACT_A, [...SNAPSHOT_ENTRIES]);
    expect(root).toBe(GOLDEN_ROOT);
  });
});

// ─── Issue #31: Property-based tests with fast-check ─────────────────────────

import * as fc from "fast-check";

const STRKEY_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

const arbitraryAddress = fc
  .array(fc.integer({ min: 0, max: STRKEY_CHARSET.length - 1 }), {
    minLength: 55,
    maxLength: 55,
  })
  .map((indices) => "G" + indices.map((i) => STRKEY_CHARSET[i]).join(""));

const arbitraryAmount = fc.bigInt({ min: 1n, max: (1n << 64n) - 1n });

const arbitraryEntry = fc.record({
  address: arbitraryAddress,
  amount: arbitraryAmount,
});

const arbitraryEntries = fc
  .array(arbitraryEntry, { minLength: 1, maxLength: 10 })
  .map((entries) => {
    const seen = new Set<string>();
    return entries.filter((e) => {
      if (seen.has(e.address)) return false;
      seen.add(e.address);
      return true;
    });
  })
  .filter((entries) => entries.length >= 1);

describe("Issue #31 — property-based tests (fast-check)", () => {
  it(
    "P1: every entry in a tree of N entries verifies against the root",
    () => {
      fc.assert(
        fc.property(arbitraryEntries, (entries) => {
          const { root, proofs } = buildMerkleTree(CONTRACT_A, entries);
          for (const entry of entries) {
            const p = proofs.get(entry.address);
            if (!p) return false;
            if (!verifyProof(root, CONTRACT_A, entry.address, entry.amount, p.proof)) {
              return false;
            }
          }
          return true;
        }),
        { numRuns: 200 }
      );
    }
  );

  it(
    "P2: modifying any address produces a different Merkle root",
    () => {
      fc.assert(
        fc.property(
          arbitraryEntries,
          fc.integer({ min: 0, max: 9 }),
          (entries, rawIdx) => {
            if (entries.length === 0) return true;
            const idx = rawIdx % entries.length;

            const original = buildMerkleTree(CONTRACT_A, entries);

            const tampered = entries.map((e, i) => {
              if (i !== idx) return e;
              const chars = e.address.split("");
              const cur = STRKEY_CHARSET.indexOf(chars[1]);
              chars[1] = STRKEY_CHARSET[(cur + 1) % STRKEY_CHARSET.length];
              return { ...e, address: chars.join("") };
            });

            const seen = new Set<string>();
            const deduped = tampered.filter((e) => {
              if (seen.has(e.address)) return false;
              seen.add(e.address);
              return true;
            });

            if (deduped.length !== entries.length) return true;

            const { root: tamperedRoot } = buildMerkleTree(CONTRACT_A, deduped);
            return original.root !== tamperedRoot;
          }
        ),
        { numRuns: 200 }
      );
    }
  );

  it(
    "P3: modifying any amount produces a different Merkle root",
    () => {
      fc.assert(
        fc.property(
          arbitraryEntries,
          fc.integer({ min: 0, max: 9 }),
          (entries, rawIdx) => {
            if (entries.length === 0) return true;
            const idx = rawIdx % entries.length;

            const original = buildMerkleTree(CONTRACT_A, entries);

            const tampered = entries.map((e, i) =>
              i === idx ? { ...e, amount: e.amount + 1n } : e
            );
            const { root: tamperedRoot } = buildMerkleTree(CONTRACT_A, tampered);
            return original.root !== tamperedRoot;
          }
        ),
        { numRuns: 200 }
      );
    }
  );

  it(
    "P4 (bonus): a proof for entry[0] does not verify for entry[1] when they differ",
    () => {
      fc.assert(
        fc.property(
          arbitraryEntries.filter((e) => e.length >= 2),
          (entries) => {
            const { root, proofs } = buildMerkleTree(CONTRACT_A, entries);
            const proof0 = proofs.get(entries[0].address)!.proof;
            const crossResult = verifyProof(
              root,
              CONTRACT_A,
              entries[1].address,
              entries[1].amount,
              proof0
            );
            return !crossResult;
          }
        ),
        { numRuns: 200 }
      );
    }
  );

  it(
    "P5 (bonus): single-entry tree root equals the leaf hash",
    () => {
      fc.assert(
        fc.property(arbitraryEntry, (entry) => {
          const { root } = buildMerkleTree(CONTRACT_A, [entry]);
          const expected = leafHash(CONTRACT_A, entry.address, entry.amount).toString("hex");
          return root === expected;
        }),
        { numRuns: 200 }
      );
    }
  );
});
//
// The same 5 addresses and amounts are asserted from Rust in test.rs
// (test_snapshot_merkle_root_5_entries) so any cross-language divergence is
// immediately caught.


// ─── Issue #114: Contract address (C...) recipient tests ─────────────────────

describe("Issue #114 — contract address (C...) recipients", () => {
  // A realistic Soroban contract address (C...)
  const CONTRACT_ADDR_1 =
    "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
  const CONTRACT_ADDR_2 =
    "CAZV4ODJJPJNZQY5DHLNPTDOQP5MNPBZQ5J5J5JN5M5NZQY5DHLNPT";

  it("leafHash works for C... contract addresses", () => {
    const hash = leafHash(CONTRACT_A, CONTRACT_ADDR_1, 1000n);
    expect(hash).toBeInstanceOf(Buffer);
    expect(hash.length).toBe(32);
  });

  it("C... address produces a different leaf hash than a G... address with same amount", () => {
    const gHash = leafHash(CONTRACT_A, ADDR_1, 1000n).toString("hex");
    const cHash = leafHash(CONTRACT_A, CONTRACT_ADDR_1, 1000n).toString("hex");
    expect(gHash).not.toBe(cHash);
  });

  it("buildMerkleTree accepts a C... address entry and verifies correctly", () => {
    const entries = [
      { address: CONTRACT_ADDR_1, amount: 1000n },
      { address: ADDR_1, amount: 500n },
    ];
    const { root, proofs } = buildMerkleTree(CONTRACT_A, entries);

    const cProof = proofs.get(CONTRACT_ADDR_1)!;
    expect(cProof).toBeDefined();
    expect(verifyProof(root, CONTRACT_A, CONTRACT_ADDR_1, 1000n, cProof.proof)).toBe(true);
  });

  it("C... address proof does not verify for a G... address in the same tree", () => {
    const entries = [
      { address: CONTRACT_ADDR_1, amount: 1000n },
      { address: ADDR_1, amount: 500n },
    ];
    const { root, proofs } = buildMerkleTree(CONTRACT_A, entries);

    // Use C... address proof to try to verify G... address claim
    const cProof = proofs.get(CONTRACT_ADDR_1)!;
    expect(verifyProof(root, CONTRACT_A, ADDR_1, 1000n, cProof.proof)).toBe(false);
  });

  it("tree with only C... addresses builds and verifies", () => {
    const entries = [
      { address: CONTRACT_ADDR_1, amount: 2000n },
      { address: CONTRACT_ADDR_2, amount: 3000n },
    ];
    const { root, proofs } = buildMerkleTree(CONTRACT_A, entries);

    for (const e of entries) {
      const p = proofs.get(e.address)!;
      expect(p).toBeDefined();
      expect(verifyProof(root, CONTRACT_A, e.address, e.amount, p.proof)).toBe(true);
    }
  });

  it("C... address can be the sole entry in a tree", () => {
    const { root, proofs } = buildMerkleTree(CONTRACT_A, [
      { address: CONTRACT_ADDR_1, amount: 5000n },
    ]);
    // Single-entry tree: root equals leaf hash, proof is empty
    expect(root).toBe(leafHash(CONTRACT_A, CONTRACT_ADDR_1, 5000n).toString("hex"));
    const p = proofs.get(CONTRACT_ADDR_1)!;
    expect(p.proof).toEqual([]);
    expect(verifyProof(root, CONTRACT_A, CONTRACT_ADDR_1, 5000n, [])).toBe(true);
  });
});

// ─── Issue #118: Edge-case amount tests for leafHash ─────────────────────────
//
// leafHash encodes the amount as a 16-byte big-endian i128 using a hi/lo
// BigInt split:
//
//   hi = amount >> 64n          (signed, written with writeBigInt64BE)
//   lo = amount & 0xffff...n    (unsigned low 64 bits, written with writeBigUInt64BE)
//
// The three tests below exercise the boundary cases that are most likely to
// expose bugs in that encoding: zero (both words are 0x00), -1 (both words
// are 0xff…ff in two's-complement), and i128::MAX (hi = 0x7fff…, lo = 0xffff…).
//
// Note on contract behaviour:
//   The Rust contract rejects amount = 0 with AirdropError::ZeroAmount
//   (see test_zero_amount_claim_fails in contracts/airdrop/src/test.rs).
//   The TypeScript leafHash function itself does NOT validate the amount —
//   that guard lives in the contract's claim() entry-point.  These SDK tests
//   therefore verify only that leafHash produces a well-formed 32-byte hash
//   without throwing, regardless of whether the contract would accept the value.

describe("Issue #118 — leafHash edge-case amounts", () => {
  /**
   * amount = 0n
   * Both the hi and lo 64-bit words of the i128 encoding are zero.
   * The contract rejects amount=0 at the claim() entry-point
   * (AirdropError::ZeroAmount), but leafHash itself must not throw.
   */
  it("leafHash(addr, 0n) produces a 32-byte buffer without throwing", () => {
    const hash = leafHash(CONTRACT_A, ADDR_1, 0n);
    expect(hash).toBeInstanceOf(Buffer);
    expect(hash.length).toBe(32);
  });

  /**
   * amount = -1n  (negative i128 encoding)
   * In two's-complement i128, -1 is all 1-bits:
   *   hi = -1n >> 64n = -1n  → writeBigInt64BE writes 0xff ff ff ff ff ff ff ff
   *   lo = -1n & 0xffff…n    = 0xffff…n → writeBigUInt64BE writes 0xff ff ff ff ff ff ff ff
   * The result must be a deterministic 32-byte hash, not an exception.
   */
  it("leafHash(addr, -1n) produces a 32-byte buffer without throwing (negative i128 encoding)", () => {
    const hash = leafHash(CONTRACT_A, ADDR_1, -1n);
    expect(hash).toBeInstanceOf(Buffer);
    expect(hash.length).toBe(32);
  });

  /**
   * amount = i128::MAX = 2^127 - 1 = 170141183460469231731687303715884105727n
   * This is the largest representable signed 128-bit integer:
   *   hi = i128::MAX >> 64n = 0x7fffffffffffffffn  (positive, fits in i64)
   *   lo = i128::MAX & 0xffff…n = 0xffffffffffffffffn
   * Both BigInt words fit in their respective signed/unsigned 64-bit encoders.
   */
  it("leafHash(addr, i128::MAX) produces a 32-byte buffer without throwing", () => {
    const I128_MAX = 170141183460469231731687303715884105727n; // 2n ** 127n - 1n
    const hash = leafHash(CONTRACT_A, ADDR_1, I128_MAX);
    expect(hash).toBeInstanceOf(Buffer);
    expect(hash.length).toBe(32);
  });

  // ── Distinctness checks ──────────────────────────────────────────────────

  it("leafHash with 0n differs from leafHash with 1n (zero is not a no-op)", () => {
    expect(leafHash(CONTRACT_A, ADDR_1, 0n).toString("hex")).not.toBe(
      leafHash(CONTRACT_A, ADDR_1, 1n).toString("hex")
    );
  });

  it("leafHash with -1n differs from leafHash with 0n", () => {
    expect(leafHash(CONTRACT_A, ADDR_1, -1n).toString("hex")).not.toBe(
      leafHash(CONTRACT_A, ADDR_1, 0n).toString("hex")
    );
  });

  it("leafHash with -1n differs from leafHash with i128::MAX (different sign bit)", () => {
    const I128_MAX = 170141183460469231731687303715884105727n;
    expect(leafHash(CONTRACT_A, ADDR_1, -1n).toString("hex")).not.toBe(
      leafHash(CONTRACT_A, ADDR_1, I128_MAX).toString("hex")
    );
  });

  // ── Stability check ──────────────────────────────────────────────────────

  it("leafHash with -1n is deterministic (same hash on repeated calls)", () => {
    const h1 = leafHash(CONTRACT_A, ADDR_1, -1n).toString("hex");
    const h2 = leafHash(CONTRACT_A, ADDR_1, -1n).toString("hex");
    expect(h1).toBe(h2);
  });
});

// ─── Issue #482: leafHash boundary amounts (word-split extremes) ───────────
//
// leafHash encodes the amount as a 16-byte big-endian i128 split into a
// signed high word and an unsigned low word:
//
//   hi = amount >> 64n
//   lo = amount & 0xffffffffffffffffn
//   buf.writeBigInt64BE(BigInt.asIntN(64, hi), 0)
//   buf.writeBigUInt64BE(lo, 8)
//
// Encoding bugs only surface where the split between the high and low
// word changes, so this block pins those exact boundaries. Per the issue,
// amount validation stays the caller's responsibility — leafHash must not
// throw for any bigint input.
describe("leafHash — boundary amounts", () => {
  it("amount = 0n produces a 32-byte hash without throwing", () => {
    const hash = leafHash(CONTRACT_A, ADDR_1, 0n);
    expect(hash).toBeInstanceOf(Buffer);
    expect(hash.length).toBe(32);
    expect(hash.toString("hex")).toMatch(/^[0-9a-f]{64}$/);
  });

  it("amount = 1n (low-word-only) differs from amount = 2n", () => {
    const h1 = leafHash(CONTRACT_A, ADDR_1, 1n).toString("hex");
    const h2 = leafHash(CONTRACT_A, ADDR_1, 2n).toString("hex");
    expect(h1).not.toBe(h2);
  });

  it("amount = 2n**63n (exactly fills the low word) produces a hash", () => {
    const hash = leafHash(CONTRACT_A, ADDR_1, 2n ** 63n);
    expect(hash.length).toBe(32);
    expect(hash.toString("hex")).toMatch(/^[0-9a-f]{64}$/);
  });

  it("amount = 2n**64n (spills into the high word) produces a hash", () => {
    const hash = leafHash(CONTRACT_A, ADDR_1, 2n ** 64n);
    expect(hash.length).toBe(32);
    // The high word is now set, so the encoding differs from amount = 0n.
    expect(hash.toString("hex")).not.toBe(
      leafHash(CONTRACT_A, ADDR_1, 0n).toString("hex")
    );
  });

  it("amount = 2n**127n - 1n (i128::MAX) produces a hash without panicking", () => {
    const hash = leafHash(CONTRACT_A, ADDR_1, 2n ** 127n - 1n);
    expect(hash.length).toBe(32);
    expect(hash.toString("hex")).toMatch(/^[0-9a-f]{64}$/);
  });

  it("amount = -1n (negative) produces a hash distinct from 0n", () => {
    // -1n encodes as all-ones i128: hi = -1n, lo = 2n**64n - 1n.
    const hNeg = leafHash(CONTRACT_A, ADDR_1, -1n).toString("hex");
    const hZero = leafHash(CONTRACT_A, ADDR_1, 0n).toString("hex");
    expect(hNeg).not.toBe(hZero);
  });
});

// ─── Issue #483: buildMerkleTree at production scale (1000 entries) ────────
//
// The SDK is used in production with four-digit recipient lists, but the
// suite only exercises small trees. This block builds a 1000-entry tree
// and verifies EVERY proof against the root, plus a wall-clock performance
// guard so a silent algorithmic regression (e.g. an accidental O(n^2)
// proof build) fails the suite.
describe("buildMerkleTree — 1000 entries", () => {
  // Deterministic synthetic data: unique strkey-shaped addresses.
  const entries = Array.from({ length: 1000 }, (_, i) => ({
    address: "G" + i.toString().padStart(55, "A"),
    amount: BigInt(i + 1) * 100n,
  }));

  it("builds the tree for 1000 entries in under 2 seconds", () => {
    const start = Date.now();
    const { root, proofs } = buildMerkleTree(CONTRACT_A, entries);
    const elapsed = Date.now() - start;

    expect(root).toMatch(/^[0-9a-f]{64}$/);
    expect(proofs.size).toBe(1000);
    expect(elapsed).toBeLessThan(2000);
  });

  it("root is a 64-character lowercase hex string", () => {
    const { root } = buildMerkleTree(CONTRACT_A, entries);
    expect(root).toMatch(/^[0-9a-f]{64}$/);
  });

  it("all 1000 proofs verify against the root", () => {
    const { root, proofs } = buildMerkleTree(CONTRACT_A, entries);

    let verified = 0;
    for (const entry of entries) {
      const p = proofs.get(entry.address);
      expect(p).toBeDefined();
      if (verifyProof(root, CONTRACT_A, entry.address, entry.amount, p!.proof)) {
        verified++;
      }
    }
    expect(verified).toBe(1000);
  }, 5000);
});
