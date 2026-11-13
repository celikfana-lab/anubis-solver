// Runs every binding against the real library: `dotnet run` in bindings/csharp/tests.
using System.Text;
using AnubisSolver;

int pass = 0, fail = 0;

void Check(string name, Action fn)
{
    try { fn(); Console.WriteLine($"  ok   {name}"); pass++; }
    catch (Exception e) { Console.WriteLine($"  FAIL {name}: {e.Message}"); fail++; }
}

void Eq<T>(T got, T want, string what = "")
{
    if (!EqualityComparer<T>.Default.Equals(got, want))
        throw new Exception($"{what} got {got}, want {want}");
}

const string HexChallenge = "00112233445566778899aabbccddeeff";
var digestOk = new System.Text.RegularExpressions.Regex("^[0-9a-f]{64}$");

var info = Anubis.GetInfo();
Console.WriteLine($"version {info.Version} | gpu {info.Gpu ?? "none"} | threads {info.Threads} | " +
                  $"affinity {info.Affinity} | batch {info.BatchWidth} | gpuVerify {info.GpuVerify}");
Console.WriteLine();

Check("info looks sane", () =>
{
    if (!System.Text.RegularExpressions.Regex.IsMatch(info.Version, @"^\d+\.\d+\.\d+$"))
        throw new Exception($"version {info.Version}");
    if (info.Threads < 1) throw new Exception($"threads {info.Threads}");
});

Check("sha256Hex matches a known digest", () =>
    Eq(Anubis.Sha256Hex("abc"),
       "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));

Check("sha256Midstate returns 8 words and rejects 63 bytes", () =>
{
    var words = Anubis.Sha256Midstate(new string('a', 64));
    Eq(words.Length, 8);
    try { Anubis.Sha256Midstate(new string('a', 63)); throw new Exception("should have thrown"); }
    catch (SolverException e) { if (!e.IsArgument) throw; }
});

Check("nibbles: solve and verify", () =>
{
    var r = Anubis.SolveNibbles("demo-challenge", 3);
    if (!digestOk.IsMatch(r.Hash)) throw new Exception($"hash {r.Hash}");
    var (ok, hash) = Anubis.VerifyNibbles("demo-challenge", r.Nonce, 3);
    if (!ok) throw new Exception($"nonce {r.Nonce} did not verify");
    Eq(hash, r.Hash);
});

Check("nibbles: a wrong nonce does not verify", () =>
{
    var (ok, _) = Anubis.VerifyNibbles("demo-challenge", 999_999, 3);
    if (ok) throw new Exception("a wrong nonce verified");
});

Check("sha256 (wasm): solve and verify", () =>
{
    var r = Anubis.SolveSha256(HexChallenge, 8);
    var (ok, hash) = Anubis.VerifySha256(HexChallenge, (uint)r.Nonce, 8);
    if (!ok) throw new Exception("did not verify");
    Eq(hash, r.Hash);
});

Check("argon2id: solve and verify", () =>
{
    var r = Anubis.SolveArgon2id(HexChallenge, 4);
    var (ok, _) = Anubis.VerifyArgon2id(HexChallenge, (uint)r.Nonce, 4);
    if (!ok) throw new Exception("did not verify");
});

Check("hashx: solve and verify", () =>
{
    var r = Anubis.SolveHashx(HexChallenge, 4);
    var (ok, _) = Anubis.VerifyHashx(HexChallenge, (uint)r.Nonce, 4);
    if (!ok) throw new Exception("did not verify");
});

Check("generic dispatcher routes every algorithm", () =>
{
    foreach (var (algo, challenge, dif) in new[]
    {
        ("fast", "demo-challenge", 2),
        ("sha256", HexChallenge, 4),
        ("argon2id", HexChallenge, 4),
        ("hashx", HexChallenge, 4),
    })
    {
        var r = Anubis.Solve(algo, challenge, dif);
        if (!digestOk.IsMatch(r.Hash)) throw new Exception($"{algo}: hash {r.Hash}");
    }
});

Check("an unknown algorithm throws ArgumentException", () =>
{
    try { Anubis.Solve("md5", "x", 1); throw new Exception("should have thrown"); }
    catch (ArgumentException) { }
});

Check("an unsolvable budget throws SolverException.IsUnsolved", () =>
{
    try
    {
        Anubis.SolveNibbles("demo-challenge", 64, new SolveOptions { BudgetMs = 1 });
        throw new Exception("should have thrown");
    }
    catch (SolverException e) { if (!e.IsUnsolved) throw; }
});

Check("malformed hex throws SolverException.IsArgument", () =>
{
    try { Anubis.SolveSha256("not-hex", 4); throw new Exception("should have thrown"); }
    catch (SolverException e) { if (!e.IsArgument) throw; }
});

Check("an independently computed digest matches the solver", () =>
{
    var r = Anubis.SolveSha256(HexChallenge, 4);
    var raw = Convert.FromHexString(HexChallenge);
    // the core picks the nonce byte order from the challenge's last byte
    var le = raw.Length > 0 && raw[^1] >= 0x80;
    var n = (uint)r.Nonce;
    var nb = le
        ? new[] { (byte)n, (byte)(n >> 8), (byte)(n >> 16), (byte)(n >> 24) }
        : new[] { (byte)(n >> 24), (byte)(n >> 16), (byte)(n >> 8), (byte)n };
    var buf = new byte[raw.Length + 4];
    raw.CopyTo(buf, 0);
    nb.CopyTo(buf, raw.Length);
    Eq(Anubis.Sha256Hex(buf), r.Hash, "digest");
});

Console.WriteLine();
Console.WriteLine($"{pass} passed, {fail} failed");
return fail == 0 ? 0 : 1;
