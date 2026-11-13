// C# bindings for libanubis_solver — solve Anubis proof-of-work challenges.
//
//   var r = Anubis.SolveNibbles("demo-challenge", 3);
//   Console.WriteLine($"{r.Nonce} {r.Hash} {r.Millis}ms");
//
// Plain P/Invoke (LibraryImport), so there is no NuGet dependency and no native
// shim: this file plus libanubis_solver.so is the whole binding.
//
// Build the library first, from the repository root:  make
// The library is looked for next to this assembly, then in the repository root,
// then along the normal loader path.

using System;
using System.IO;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace AnubisSolver
{
    /// <summary>A solved challenge.</summary>
    public readonly record struct SolveResult(ulong Nonce, string Hash, double Millis);

    /// <summary>Machine and library facts.</summary>
    public readonly record struct Info(
        string Version, string? Gpu, int Threads, string? Affinity, int BatchWidth, bool GpuVerify);

    /// <summary>Optional knobs. The default is "pick threads, no limits".</summary>
    public sealed class SolveOptions
    {
        /// <summary>Worker threads; 0 = the library default.</summary>
        public int Threads { get; init; }
        /// <summary>Bound on the nonce search; 0 = no limit.</summary>
        public long MaxNonce { get; init; }
        /// <summary>Time budget in ms; 0 = no limit.</summary>
        public double BudgetMs { get; init; }
    }

    /// <summary>Thrown when the C library returns a non-zero code.</summary>
    public sealed class SolverException : Exception
    {
        public int Code { get; }
        public SolverException(string what, int code, string detail)
            : base($"{what}: {detail} (code {code})") => Code = code;

        public bool IsUnsolved => Code == Anubis.ERR_UNSOLVED;
        public bool IsArgument => Code == Anubis.ERR_ARG;
    }

    /// <summary>Static bindings over libanubis_solver.</summary>
    public static partial class Anubis
    {
        private const string Lib = "libanubis_solver";

        public const int OK = 0;
        public const int ERR_ARG = 1;
        public const int ERR_UNSOLVED = 2;
        public const int ERR_INTERNAL = 3;

        static Anubis()
        {
            // The .so usually sits in the repository root next to the built
            // assembly; teach the loader about it before any DllImport runs.
            NativeLibrary.SetDllImportResolver(typeof(Anubis).Assembly, Resolve);
        }

        private static IntPtr Resolve(string name, Assembly assembly, DllImportSearchPath? path)
        {
            if (name != Lib) return IntPtr.Zero;
            foreach (var candidate in Candidates())
            {
                if (File.Exists(candidate) && NativeLibrary.TryLoad(candidate, out var h)) return h;
            }
            return IntPtr.Zero; // fall back to the default search
        }

        private static IEnumerable<string> Candidates()
        {
            var env = Environment.GetEnvironmentVariable("ANUBIS_LIB");
            if (!string.IsNullOrEmpty(env)) yield return env;

            // walk up from the build output until the repository root; do not
            // stop at the first .csproj, the library lives above bindings/
            var dir = AppContext.BaseDirectory;
            for (var d = new DirectoryInfo(dir); d != null; d = d.Parent)
            {
                yield return Path.Combine(d.FullName, "libanubis_solver.so");
                yield return Path.Combine(d.FullName, "libanubis_solver.dylib");
            }
            yield return Path.Combine(Environment.CurrentDirectory, "libanubis_solver.so");
        }

        /* ------------------------------------------------------- introspection */

        [LibraryImport(Lib)] private static partial IntPtr anubis_solver_version();
        [LibraryImport(Lib)] private static partial IntPtr anubis_gpu_info();
        [LibraryImport(Lib)] private static partial int anubis_default_threads();
        [LibraryImport(Lib)] private static partial IntPtr anubis_cpu_affinity_info();
        [LibraryImport(Lib)] private static partial int anubis_batch_width();
        [LibraryImport(Lib)] private static partial void anubis_set_gpu_verify(int enable);
        [LibraryImport(Lib)] private static partial int anubis_gpu_verify();

        private static string? Utf8(IntPtr p) =>
            p == IntPtr.Zero ? null : Marshal.PtrToStringUTF8(p);

        public static string Version => Utf8(anubis_solver_version()) ?? "";
        public static string? GpuInfo => Utf8(anubis_gpu_info());
        public static int DefaultThreads => anubis_default_threads();
        public static string? CpuAffinity => Utf8(anubis_cpu_affinity_info());
        public static int BatchWidth => anubis_batch_width();
        public static void SetGpuVerify(bool enable) => anubis_set_gpu_verify(enable ? 1 : 0);
        public static bool GpuVerify => anubis_gpu_verify() != 0;

        public static Info GetInfo() => new(
            Version, GpuInfo, DefaultThreads, CpuAffinity, BatchWidth, GpuVerify);

        /* ------------------------------------------------------------ sha256 */

        [LibraryImport(Lib, EntryPoint = "anubis_sha256_hex")]
        private static partial int sha256_hex_str(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string data, UIntPtr len, byte[] outHex);

        /* The C function is byte-orientated and takes an explicit length, so it
         * takes raw bytes as well as strings. Without this overload a digest
         * over binary data cannot be computed at all. */
        [LibraryImport(Lib, EntryPoint = "anubis_sha256_hex")]
        private static partial int sha256_hex_bytes(byte[] data, UIntPtr len, byte[] outHex);

        [LibraryImport(Lib, EntryPoint = "anubis_sha256_midstate")]
        private static partial int sha256_midstate_str(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string data, UIntPtr len, uint[] outWords);

        [LibraryImport(Lib, EntryPoint = "anubis_sha256_midstate")]
        private static partial int sha256_midstate_bytes(byte[] data, UIntPtr len, uint[] outWords);

        /// <summary>Lowercase hex SHA-256 of a UTF-8 string.</summary>
        public static string Sha256Hex(string data)
        {
            var outHex = new byte[65];
            var rc = sha256_hex_str(data, (UIntPtr)Encoding.UTF8.GetByteCount(data), outHex);
            Throw(rc, "anubis_sha256_hex");
            return Encoding.ASCII.GetString(outHex, 0, Array.IndexOf(outHex, (byte)0));
        }

        /// <summary>Lowercase hex SHA-256 of arbitrary bytes.</summary>
        public static string Sha256Hex(ReadOnlySpan<byte> data)
        {
            var outHex = new byte[65];
            var buf = data.ToArray();
            var rc = sha256_hex_bytes(buf, (UIntPtr)buf.Length, outHex);
            Throw(rc, "anubis_sha256_hex");
            return Encoding.ASCII.GetString(outHex, 0, Array.IndexOf(outHex, (byte)0));
        }

        /// <summary>Midstate after <paramref name="data"/>, length a multiple of 64.</summary>
        public static uint[] Sha256Midstate(string data)
        {
            var bytes = Encoding.UTF8.GetByteCount(data);
            if (bytes % 64 != 0) throw new SolverException("Sha256Midstate", ERR_ARG, "length must be a multiple of 64");
            var words = new uint[8];
            var rc = sha256_midstate_str(data, (UIntPtr)bytes, words);
            Throw(rc, "anubis_sha256_midstate");
            return words;
        }

        /// <summary>Midstate after arbitrary bytes, length a multiple of 64.</summary>
        public static uint[] Sha256Midstate(ReadOnlySpan<byte> data)
        {
            if (data.Length % 64 != 0)
                throw new SolverException("Sha256Midstate", ERR_ARG, "length must be a multiple of 64");
            var words = new uint[8];
            var buf = data.ToArray();
            var rc = sha256_midstate_bytes(buf, (UIntPtr)buf.Length, words);
            Throw(rc, "anubis_sha256_midstate");
            return words;
        }

        /* ------------------------------------------------------------ solving */

        [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
        private static partial int anubis_solve_nibbles(
            string challenge, int difficulty, int threads, long maxNonce, double budgetMs,
            out ulong nonce, byte[] outHex, out double ms);

        [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
        private static partial int anubis_solve_bits(
            string challengeHex, int difficulty, int threads, double budgetMs,
            out uint nonce, byte[] outHex, out double ms);

        [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
        private static partial int anubis_solve_argon2id(
            string challengeHex, int difficulty, int threads, double budgetMs,
            out uint nonce, byte[] outHex, out double ms);

        [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
        private static partial int anubis_solve_hashx(
            string challengeHex, int difficulty, int threads, double budgetMs,
            out uint nonce, byte[] outHex, out double ms);

        private static string Hex(byte[] buf)
        {
            var end = Array.IndexOf(buf, (byte)0);
            return Encoding.ASCII.GetString(buf, 0, end < 0 ? buf.Length : end);
        }

        /// <summary>`fast` / `slow`: leading zero nibbles.</summary>
        public static SolveResult SolveNibbles(string challenge, int difficulty, SolveOptions? o = null)
        {
            o ??= new SolveOptions();
            var hex = new byte[65];
            var maxNonce = o.MaxNonce == 0 ? -1 : o.MaxNonce;
            var rc = anubis_solve_nibbles(challenge, difficulty, o.Threads, maxNonce, o.BudgetMs,
                                          out var nonce, hex, out var ms);
            Throw(rc, "anubis_solve_nibbles");
            return new SolveResult(nonce, Hex(hex), ms);
        }

        /// <summary>`sha256` (wasm): leading zero bits, hex challenge.</summary>
        public static SolveResult SolveSha256(string challengeHex, int difficulty, SolveOptions? o = null) =>
            Bits(anubis_solve_bits, "anubis_solve_bits", challengeHex, difficulty, o);

        /// <summary>`argon2id`: leading zero bits.</summary>
        public static SolveResult SolveArgon2id(string challengeHex, int difficulty, SolveOptions? o = null) =>
            Bits(anubis_solve_argon2id, "anubis_solve_argon2id", challengeHex, difficulty, o);

        /// <summary>`hashx`: leading zero bits.</summary>
        public static SolveResult SolveHashx(string challengeHex, int difficulty, SolveOptions? o = null) =>
            Bits(anubis_solve_hashx, "anubis_solve_hashx", challengeHex, difficulty, o);

        private delegate int BitsFn(string a, int b, int c, double d, out uint e, byte[] f, out double g);

        private static SolveResult Bits(BitsFn fn, string what, string challengeHex,
                                       int difficulty, SolveOptions? o)
        {
            o ??= new SolveOptions();
            var hex = new byte[65];
            var rc = fn(challengeHex, difficulty, o.Threads, o.BudgetMs, out var nonce, hex, out var ms);
            Throw(rc, what);
            return new SolveResult(nonce, Hex(hex), ms);
        }

        /// <summary>Dispatch on the algorithm name Anubis uses.</summary>
        public static SolveResult Solve(string algorithm, string challenge, int difficulty, SolveOptions? o = null) =>
            algorithm switch
            {
                "fast" or "slow" => SolveNibbles(challenge, difficulty, o),
                "sha256" or "wasm-sha256" => SolveSha256(challenge, difficulty, o),
                "argon2id" => SolveArgon2id(challenge, difficulty, o),
                "hashx" => SolveHashx(challenge, difficulty, o),
                _ => throw new ArgumentException($"unknown algorithm: {algorithm}", nameof(algorithm)),
            };

        /* ---------------------------------------------------------- verifying */

        [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
        private static partial int anubis_verify_nibbles(
            string challenge, ulong nonce, int difficulty, byte[] outHex);

        [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
        private static partial int anubis_verify_bits(
            string challengeHex, uint nonce, int difficulty, byte[] outHex);

        [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
        private static partial int anubis_verify_argon2id(
            string challengeHex, uint nonce, int difficulty, byte[] outHex);

        [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
        private static partial int anubis_verify_hashx(
            string challengeHex, uint nonce, int difficulty, byte[] outHex);

        /// <summary>Re-check a `fast`/`slow` nonce.</summary>
        public static (bool Ok, string Hash) VerifyNibbles(string challenge, ulong nonce, int difficulty) =>
            Verify((a, b, c, d) => anubis_verify_nibbles(a, (ulong)b, c, d), challenge, nonce, difficulty);

        public static (bool Ok, string Hash) VerifySha256(string challengeHex, uint nonce, int difficulty) =>
            Verify((a, b, c, d) => anubis_verify_bits(a, (uint)b, c, d), challengeHex, nonce, difficulty);

        public static (bool Ok, string Hash) VerifyArgon2id(string challengeHex, uint nonce, int difficulty) =>
            Verify((a, b, c, d) => anubis_verify_argon2id(a, (uint)b, c, d), challengeHex, nonce, difficulty);

        public static (bool Ok, string Hash) VerifyHashx(string challengeHex, uint nonce, int difficulty) =>
            Verify((a, b, c, d) => anubis_verify_hashx(a, (uint)b, c, d), challengeHex, nonce, difficulty);

        private delegate int VerifyFn(string challenge, ulong nonce, int difficulty, byte[] outHex);

        private static (bool, string) Verify(VerifyFn fn, string challenge, ulong nonce, int difficulty)
        {
            var hex = new byte[65];
            var rc = fn(challenge, nonce, difficulty, hex);
            if (rc != OK && rc != ERR_UNSOLVED) Throw(rc, "verify");
            return (rc == OK, Hex(hex));
        }

        private static void Throw(int rc, string what)
        {
            if (rc == OK) return;
            var detail = rc switch
            {
                ERR_ARG => "invalid argument",
                ERR_UNSOLVED => "exhausted the nonce or time budget",
                ERR_INTERNAL => "internal error",
                _ => "unknown return code",
            };
            throw new SolverException(what, rc, detail);
        }
    }
}
