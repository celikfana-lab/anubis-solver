import io.github.celikfana.anubis.Anubis;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

/** Runs every binding against the real library. No JUnit, no dependencies. */
public final class AnubisTest {

    private static int pass, fail;

    private static void check(String name, Runnable fn) {
        try {
            fn.run();
            System.out.println("  ok   " + name);
            pass++;
        } catch (Throwable t) {
            System.out.println("  FAIL " + name + ": " + t.getMessage());
            fail++;
        }
    }

    private static void eq(Object got, Object want) {
        if (!got.equals(want)) throw new AssertionError("got " + got + ", want " + want);
    }

    private static void assertTrue(boolean b, String what) {
        if (!b) throw new AssertionError(what);
    }

    public static void main(String[] args) {
        final String hexChallenge = "00112233445566778899aabbccddeeff";

        Anubis.Info i = Anubis.info();
        System.out.printf("version %s | gpu %s | threads %d | affinity %s | batch %d%n%n",
                i.version(), i.gpu() == null ? "none" : i.gpu(), i.threads(),
                i.affinity(), i.batchWidth());

        check("info looks sane", () -> {
            assertTrue(i.version().matches("\\d+\\.\\d+\\.\\d+"), "version " + i.version());
            assertTrue(i.threads() >= 1, "threads " + i.threads());
        });

        check("sha256Hex matches a known digest", () -> eq(Anubis.sha256Hex("abc"),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));

        check("sha256Hex over bytes equals the same bytes as text", () -> eq(
                Anubis.sha256Hex("abc".getBytes(StandardCharsets.US_ASCII)),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));

        check("sha256Hex of empty input is the empty digest", () ->
                eq(Anubis.sha256Hex(new byte[0]),
                   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));

        check("sha256Midstate returns 8 words and rejects 63 bytes", () -> {
            long[] w = Anubis.sha256Midstate("a".repeat(64).getBytes(StandardCharsets.US_ASCII));
            eq(w.length, 8);
            try {
                Anubis.sha256Midstate(new byte[63]);
                throw new AssertionError("63 bytes should have been rejected");
            } catch (Anubis.SolverException e) {
                assertTrue(e.isArgument(), "expected ERR_ARG, got " + e.code());
            }
        });

        check("nibbles: solve and verify", () -> {
            Anubis.Result r = Anubis.solveNibbles("demo-challenge", 3);
            assertTrue(r.hash().matches("[0-9a-f]{64}"), "hash " + r.hash());
            Anubis.Verdict v = Anubis.verifyNibbles("demo-challenge", r.nonce(), 3);
            assertTrue(v.ok(), "nonce " + r.nonce() + " did not verify");
            eq(v.hash(), r.hash());
        });

        check("nibbles: a wrong nonce does not verify", () ->
                assertTrue(!Anubis.verifyNibbles("demo-challenge", 999_999, 3).ok(),
                        "a wrong nonce verified"));

        check("sha256 (wasm): solve and verify", () -> {
            Anubis.Result r = Anubis.solveSha256(hexChallenge, 8);
            Anubis.Verdict v = Anubis.verifySha256(hexChallenge, r.nonce(), 8);
            assertTrue(v.ok(), "did not verify");
            eq(v.hash(), r.hash());
        });

        check("argon2id: solve and verify", () -> {
            Anubis.Result r = Anubis.solveArgon2id(hexChallenge, 4);
            assertTrue(Anubis.verifyArgon2id(hexChallenge, r.nonce(), 4).ok(), "did not verify");
        });

        check("hashx: solve and verify", () -> {
            Anubis.Result r = Anubis.solveHashx(hexChallenge, 4);
            assertTrue(Anubis.verifyHashx(hexChallenge, r.nonce(), 4).ok(), "did not verify");
        });

        check("generic dispatcher routes every algorithm", () -> {
            String[][] cases = {
                {"fast", "demo-challenge", "2"},
                {"sha256", hexChallenge, "4"},
                {"argon2id", hexChallenge, "4"},
                {"hashx", hexChallenge, "4"},
            };
            for (String[] c : cases) {
                Anubis.Result r = Anubis.solve(c[0], c[1], Integer.parseInt(c[2]));
                assertTrue(r.hash().matches("[0-9a-f]{64}"), c[0] + ": hash " + r.hash());
            }
        });

        check("an unknown algorithm is an IllegalArgumentException", () -> {
            try {
                Anubis.solve("md5", "x", 1);
                throw new AssertionError("should have thrown");
            } catch (IllegalArgumentException expected) { }
        });

        check("an unsolvable budget throws SolverException.isUnsolved", () -> {
            try {
                Anubis.solveNibbles("demo-challenge", 64, new Anubis.Options(0, -1, 1.0));
                throw new AssertionError("should have thrown");
            } catch (Anubis.SolverException e) {
                assertTrue(e.isUnsolved(), "expected ERR_UNSOLVED, got " + e.code());
            }
        });

        check("malformed hex throws SolverException.isArgument", () -> {
            try {
                Anubis.solveSha256("not-hex", 4);
                throw new AssertionError("should have thrown");
            } catch (Anubis.SolverException e) {
                assertTrue(e.isArgument(), "expected ERR_ARG, got " + e.code());
            }
        });

        check("an independently computed digest matches the solver", () -> {
            Anubis.Result r = Anubis.solveSha256(hexChallenge, 4);
            byte[] raw = HexFormat.of().parseHex(hexChallenge);
            // the core picks the nonce byte order from the challenge's last byte
            boolean le = (raw[raw.length - 1] & 0xFF) >= 0x80;
            long n = r.nonce();
            byte[] nb = le
                ? new byte[]{(byte) n, (byte) (n >> 8), (byte) (n >> 16), (byte) (n >> 24)}
                : new byte[]{(byte) (n >> 24), (byte) (n >> 16), (byte) (n >> 8), (byte) n};
            byte[] buf = new byte[raw.length + 4];
            System.arraycopy(raw, 0, buf, 0, raw.length);
            System.arraycopy(nb, 0, buf, raw.length, 4);
            eq(Anubis.sha256Hex(buf), r.hash());
        });

        System.out.printf("%n%d passed, %d failed%n", pass, fail);
        if (fail > 0) System.exit(1);
    }
}
