package io.github.celikfana.anubis;

/**
 * Solve Anubis proof-of-work challenges through libanubis_solver.so.
 *
 * <pre>{@code
 * var r = Anubis.solveNibbles("demo-challenge", 3);
 * System.out.println(r.nonce() + " " + r.hash() + " " + r.millis() + "ms");
 * }</pre>
 *
 * Plain JNI: no dependencies, no preview flags, works from Java 8 to 25. The
 * native shim ({@code libanubis_jni.so}) must be on {@code java.library.path}:
 *
 * <pre>{@code
 * java -Djava.library.path=bindings/java/build ...
 * }</pre>
 */
public final class Anubis {

    private Anubis() {}

    /** Status codes, matching anubis-solver.h. */
    public static final int OK = 0;
    public static final int ERR_ARG = 1;
    public static final int ERR_UNSOLVED = 2;
    public static final int ERR_INTERNAL = 3;

    /** A solved challenge. */
    public record Result(long nonce, String hash, double millis) {}

    /** A verification outcome. */
    public record Verdict(boolean ok, String hash) {}

    /** Machine and library facts. */
    public record Info(String version, String gpu, int threads, String affinity,
                       int batchWidth, boolean gpuVerify) {}

    /** Thrown when the native library returns a non-zero code. */
    public static final class SolverException extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final int code;

        public SolverException(String what, int code) {
            super(what + ": " + describe(code) + " (code " + code + ")");
            this.code = code;
        }

        public int code() { return code; }
        public boolean isUnsolved() { return code == ERR_UNSOLVED; }
        public boolean isArgument() { return code == ERR_ARG; }
    }

    private static String describe(int code) {
        return switch (code) {
            case ERR_ARG -> "invalid argument";
            case ERR_UNSOLVED -> "exhausted the nonce or time budget";
            case ERR_INTERNAL -> "internal error";
            default -> "unknown return code";
        };
    }

    static {
        System.loadLibrary("anubis_jni");
    }

    /* ------------------------------------------------------- native methods */

    private static native String nativeVersion();
    private static native String nativeGpuInfo();
    private static native int nativeDefaultThreads();
    private static native String nativeAffinityInfo();
    private static native int nativeBatchWidth();
    private static native void nativeSetGpuVerify(boolean enable);
    private static native boolean nativeGpuVerify();

    private static native String nativeSha256Hex(byte[] data);
    private static native long[] nativeSha256Midstate(byte[] data);

    private static native int nativeSolveNibbles(String challenge, int difficulty, int threads,
                                                 long maxNonce, double budgetMs, long[] outNonce,
                                                 byte[] outHex, double[] outMs);
    private static native int nativeSolveBits(String challengeHex, int difficulty, int threads,
                                              double budgetMs, long[] outNonce, byte[] outHex,
                                              double[] outMs);
    private static native int nativeSolveArgon2id(String challengeHex, int difficulty, int threads,
                                                  double budgetMs, long[] outNonce, byte[] outHex,
                                                  double[] outMs);
    private static native int nativeSolveHashx(String challengeHex, int difficulty, int threads,
                                               double budgetMs, long[] outNonce, byte[] outHex,
                                               double[] outMs);

    private static native int nativeVerifyNibbles(String challenge, long nonce, int difficulty,
                                                  byte[] outHex);
    private static native int nativeVerifyBits(String challengeHex, long nonce, int difficulty,
                                               byte[] outHex);
    private static native int nativeVerifyArgon2id(String challengeHex, long nonce, int difficulty,
                                                   byte[] outHex);
    private static native int nativeVerifyHashx(String challengeHex, long nonce, int difficulty,
                                                byte[] outHex);

    /* ------------------------------------------------------------ utilities */

    private static String hexOf(byte[] buf) {
        int end = 0;
        while (end < buf.length && buf[end] != 0) end++;
        return new String(buf, 0, end, java.nio.charset.StandardCharsets.US_ASCII);
    }

    private static void throwIf(int rc, String what) {
        if (rc != OK) throw new SolverException(what, rc);
    }

    /* ------------------------------------------------------ introspection */

    public static String version() { return nativeVersion(); }
    public static String gpuInfo() { return nativeGpuInfo(); }
    public static int defaultThreads() { return nativeDefaultThreads(); }
    public static String affinityInfo() { return nativeAffinityInfo(); }
    public static int batchWidth() { return nativeBatchWidth(); }
    public static void setGpuVerify(boolean enable) { nativeSetGpuVerify(enable); }
    public static boolean gpuVerify() { return nativeGpuVerify(); }

    public static Info info() {
        return new Info(version(), gpuInfo(), defaultThreads(), affinityInfo(),
                        batchWidth(), gpuVerify());
    }

    /* ---------------------------------------------------------- sha256 */

    /** Lowercase hex SHA-256 of these bytes. */
    public static String sha256Hex(byte[] data) {
        String hex = nativeSha256Hex(data);
        if (hex == null) throw new SolverException("anubis_sha256_hex", ERR_ARG);
        return hex;
    }

    /** Lowercase hex SHA-256 of a UTF-8 string. */
    public static String sha256Hex(String data) {
        return sha256Hex(data.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /** Midstate after data, whose length must be a multiple of 64. */
    public static long[] sha256Midstate(byte[] data) {
        if (data.length % 64 != 0) throw new SolverException("anubis_sha256_midstate", ERR_ARG);
        long[] words = nativeSha256Midstate(data);
        if (words == null) throw new SolverException("anubis_sha256_midstate", ERR_ARG);
        return words;
    }

    /* ----------------------------------------------------------- solving */

    /** Optional knobs; the default is "pick threads, no limits". */
    public record Options(int threads, long maxNonce, double budgetMs) {
        public static final Options DEFAULT = new Options(0, -1, 0.0);
        public static Options of(int threads) { return new Options(threads, -1, 0.0); }
    }

    private static Result solve(int family, String challenge, int difficulty, Options o) {
        Options opts = (o == null) ? Options.DEFAULT : o;
        long[] nonce = new long[1];
        byte[] hex = new byte[65];
        double[] ms = new double[1];
        int rc = switch (family) {
            case 0 -> nativeSolveNibbles(challenge, difficulty, opts.threads(),
                                         opts.maxNonce(), opts.budgetMs(), nonce, hex, ms);
            case 1 -> nativeSolveBits(challenge, difficulty, opts.threads(),
                                      opts.budgetMs(), nonce, hex, ms);
            case 2 -> nativeSolveArgon2id(challenge, difficulty, opts.threads(),
                                          opts.budgetMs(), nonce, hex, ms);
            default -> nativeSolveHashx(challenge, difficulty, opts.threads(),
                                        opts.budgetMs(), nonce, hex, ms);
        };
        throwIf(rc, family == 0 ? "anubis_solve_nibbles" : "anubis_solve");
        return new Result(nonce[0], hexOf(hex), ms[0]);
    }

    /** {@code fast} / {@code slow}: leading zero nibbles. */
    public static Result solveNibbles(String challenge, int difficulty) {
        return solve(0, challenge, difficulty, null);
    }

    public static Result solveNibbles(String challenge, int difficulty, Options o) {
        return solve(0, challenge, difficulty, o);
    }

    /** {@code sha256} (wasm): leading zero bits, hex challenge. */
    public static Result solveSha256(String challengeHex, int difficulty) {
        return solve(1, challengeHex, difficulty, null);
    }

    public static Result solveSha256(String challengeHex, int difficulty, Options o) {
        return solve(1, challengeHex, difficulty, o);
    }

    /** {@code argon2id}: leading zero bits. */
    public static Result solveArgon2id(String challengeHex, int difficulty) {
        return solve(2, challengeHex, difficulty, null);
    }

    public static Result solveArgon2id(String challengeHex, int difficulty, Options o) {
        return solve(2, challengeHex, difficulty, o);
    }

    /** {@code hashx}: leading zero bits. */
    public static Result solveHashx(String challengeHex, int difficulty) {
        return solve(3, challengeHex, difficulty, null);
    }

    public static Result solveHashx(String challengeHex, int difficulty, Options o) {
        return solve(3, challengeHex, difficulty, o);
    }

    /** Dispatch on the algorithm name Anubis puts in the challenge page. */
    public static Result solve(String algorithm, String challenge, int difficulty, Options o) {
        return switch (algorithm) {
            case "fast", "slow" -> solve(0, challenge, difficulty, o);
            case "sha256", "wasm-sha256" -> solve(1, challenge, difficulty, o);
            case "argon2id" -> solve(2, challenge, difficulty, o);
            case "hashx" -> solve(3, challenge, difficulty, o);
            default -> throw new IllegalArgumentException("unknown algorithm: " + algorithm);
        };
    }

    public static Result solve(String algorithm, String challenge, int difficulty) {
        return solve(algorithm, challenge, difficulty, null);
    }

    /* --------------------------------------------------------- verifying */

    private static Verdict verify(int family, String challenge, long nonce, int difficulty) {
        byte[] hex = new byte[65];
        int rc = switch (family) {
            case 0 -> nativeVerifyNibbles(challenge, nonce, difficulty, hex);
            case 1 -> nativeVerifyBits(challenge, nonce, difficulty, hex);
            case 2 -> nativeVerifyArgon2id(challenge, nonce, difficulty, hex);
            default -> nativeVerifyHashx(challenge, nonce, difficulty, hex);
        };
        if (rc != OK && rc != ERR_UNSOLVED) throw new SolverException("anubis_verify", rc);
        return new Verdict(rc == OK, hexOf(hex));
    }

    public static Verdict verifyNibbles(String challenge, long nonce, int difficulty) {
        return verify(0, challenge, nonce, difficulty);
    }

    public static Verdict verifySha256(String challengeHex, long nonce, int difficulty) {
        return verify(1, challengeHex, nonce, difficulty);
    }

    public static Verdict verifyArgon2id(String challengeHex, long nonce, int difficulty) {
        return verify(2, challengeHex, nonce, difficulty);
    }

    public static Verdict verifyHashx(String challengeHex, long nonce, int difficulty) {
        return verify(3, challengeHex, nonce, difficulty);
    }

    public static Verdict verify(String algorithm, String challenge, long nonce, int difficulty) {
        return switch (algorithm) {
            case "fast", "slow" -> verify(0, challenge, nonce, difficulty);
            case "sha256", "wasm-sha256" -> verify(1, challenge, nonce, difficulty);
            case "argon2id" -> verify(2, challenge, nonce, difficulty);
            case "hashx" -> verify(3, challenge, nonce, difficulty);
            default -> throw new IllegalArgumentException("unknown algorithm: " + algorithm);
        };
    }
}
