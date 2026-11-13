// Java demo: solve an Anubis challenge through libanubis_solver.
//
//   (cd bindings/java && make)                      # once
//   javac -cp bindings/java/build/classes -d /tmp/anubis-java examples/java_demo/AnubisDemo.java
//   java -Djava.library.path=bindings/java/build \
//        -cp bindings/java/build/classes:/tmp/anubis-java AnubisDemo
//
// or just: ./examples/run_all.sh java
import io.github.celikfana.anubis.Anubis;

public final class AnubisDemo {
    public static void main(String[] args) {
        Anubis.Info i = Anubis.info();
        System.out.printf("libanubis_solver %s  gpu %s  threads %d  batch %d%n",
                i.version(), i.gpu() == null ? "(none)" : i.gpu(), i.threads(), i.batchWidth());

        // fast / slow: SHA-256 over challenge || decimal nonce, leading zero nibbles
        Anubis.Result nib = Anubis.solveNibbles("demo-challenge", 3);
        System.out.printf("nibbles   nonce %d  %s  %.3f ms%n", nib.nonce(), nib.hash(), nib.millis());

        Anubis.Verdict v = Anubis.verifyNibbles("demo-challenge", nib.nonce(), 3);
        System.out.printf("verify    %s  %s%n",
                v.ok() ? "ok" : "FAILED",
                v.hash().equals(nib.hash()) ? "same digest" : "DIFFERENT digest");

        // sha256 / argon2id / hashx: leading zero bits, hex challenge
        final String hex = "00112233445566778899aabbccddeeff";
        Anubis.Result bits = Anubis.solve("sha256", hex, 8);
        System.out.printf("sha256    nonce %d  %s%n", bits.nonce(), bits.hash());
        System.out.printf("verify    %s%n",
                Anubis.verifySha256(hex, bits.nonce(), 8).ok() ? "ok" : "FAILED");

        // the library's own SHA-256, to cross-check a digest independently
        System.out.printf("sha256(\"abc\") = %s%n", Anubis.sha256Hex("abc"));

        // an exhausted budget is an exception, not a wrong answer
        try {
            Anubis.solveNibbles("demo-challenge", 64, new Anubis.Options(0, -1, 1.0));
        } catch (Anubis.SolverException e) {
            System.out.printf("unsolvable budget -> SolverException.isUnsolved=%s%n", e.isUnsolved());
        }
    }
}
