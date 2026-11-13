// C# demo: solve an Anubis challenge through libanubis_solver.
//
//   dotnet run examples/csharp_demo.cs        (from the repository root)
//
// .NET 10 file-based app: the #:project line pulls in the binding project, and
// the binding finds libanubis_solver.so by walking up from the build output and
// from the current directory - so run this from the repo root after `make`.
#:project ../bindings/csharp/AnubisSolver.csproj

using AnubisSolver;

var info = Anubis.GetInfo();
Console.WriteLine($"libanubis_solver {info.Version}  gpu {info.Gpu ?? "(none)"}  " +
                  $"threads {info.Threads}  batch {info.BatchWidth}");

// fast / slow: SHA-256 over challenge || decimal nonce, leading zero nibbles
var nib = Anubis.SolveNibbles("demo-challenge", 3);
Console.WriteLine($"nibbles   nonce {nib.Nonce}  {nib.Hash}  {nib.Millis:F3} ms");
var (ok1, hash1) = Anubis.VerifyNibbles("demo-challenge", nib.Nonce, 3);
Console.WriteLine($"verify    {(ok1 ? "ok" : "FAILED")}  {(hash1 == nib.Hash ? "same digest" : "DIFFERENT digest")}");

// sha256 / argon2id / hashx: leading zero bits, hex challenge
const string hex = "00112233445566778899aabbccddeeff";
var bits = Anubis.Solve("sha256", hex, 8);
Console.WriteLine($"sha256    nonce {bits.Nonce}  {bits.Hash}");
var (ok2, _) = Anubis.VerifySha256(hex, (uint)bits.Nonce, 8);
Console.WriteLine($"verify    {(ok2 ? "ok" : "FAILED")}");

// the library's own SHA-256, to cross-check a digest independently
Console.WriteLine($"sha256(\"abc\") = {Anubis.Sha256Hex("abc")}");
