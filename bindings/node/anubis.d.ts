/** Type declarations for the Node bindings of libanubis_solver. */

export interface Info {
  /** library version, e.g. "1.1.0" */
  version: string;
  /** active GPU backend, or null when there is none */
  gpu: string | null;
  /** default worker count (physical cores) */
  threads: number;
  /** human-readable CPU affinity, or null */
  affinity: string | null;
  /** SHA-256 batch width: 16 (AVX-512), 8 (AVX2), 0 (scalar) */
  batchWidth: number;
  /** whether GPU hits are re-checked on the CPU */
  gpuVerify: boolean;
}

export interface SolveOptions {
  /** worker threads, 0 = library default */
  threads?: number;
  /** bound on the nonce search, -1 = no limit (nibbles only) */
  maxNonce?: number | bigint;
  /** time budget in milliseconds, 0 = no limit */
  budgetMs?: number;
}

export interface SolveResult {
  nonce: number;
  /** lowercase hex SHA-256 of the winning input */
  hash: string;
  /** elapsed milliseconds */
  ms: number;
}

export interface VerifyResult {
  ok: boolean;
  hash: string;
}

export declare class SolverError extends Error {
  code: number;
  constructor(message: string, code: number);
}

export type Algorithm =
  | 'fast'
  | 'slow'
  | 'sha256'
  | 'wasm-sha256'
  | 'argon2id'
  | 'hashx';

export declare function info(): Info;
export declare function setGpuVerify(enable: boolean): void;

export declare function sha256Hex(data: string | Buffer): string;
export declare function sha256Midstate(data: string | Buffer): number[];

export declare function solveNibbles(
  challenge: string,
  difficulty: number,
  opts?: SolveOptions
): SolveResult;
export declare function solveSha256(
  challengeHex: string,
  difficulty: number,
  opts?: SolveOptions
): SolveResult;
export declare function solveArgon2id(
  challengeHex: string,
  difficulty: number,
  opts?: SolveOptions
): SolveResult;
export declare function solveHashx(
  challengeHex: string,
  difficulty: number,
  opts?: SolveOptions
): SolveResult;

export declare function solve(
  algorithm: Algorithm,
  challenge: string,
  difficulty: number,
  opts?: SolveOptions
): SolveResult;

export declare function verifyNibbles(
  challenge: string,
  nonce: number,
  difficulty: number
): VerifyResult;
export declare function verify(
  algorithm: Algorithm,
  challenge: string,
  nonce: number,
  difficulty: number
): VerifyResult;

export declare const OK: 0;
export declare const ERR_ARG: 1;
export declare const ERR_UNSOLVED: 2;
export declare const ERR_INTERNAL: 3;
export declare const libraryPath: string;
