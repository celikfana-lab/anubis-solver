# RELEASING.md

How the binaries on the release page are produced. Three targets, one machine,
no containers: two Debian 12 sysroots for the Linux architectures, qemu for the
ARM one, and mingw-w64 plus two cross-built libraries for Windows.

The reason for the sysroots is not paranoia. This host's gcc 15 defaults to
`-std=gnu23`, and glibc headers redirect `strtol` and friends to `__isoc23_*`
under `_GNU_SOURCE`, which jacks the minimum glibc up to **2.38**. A binary that
only runs on Ubuntu 24.04 and newer is not a release, it is a souvenir. Building
against bookworm's glibc 2.36 puts the floor at **2.34**, which covers Debian 12,
Ubuntu 22.04+, Raspberry Pi OS bookworm and anything newer.

Keep `-std=gnu17` in both parts of the tree anyway: it is the C standard the
code is written in, and leaving it implicit means the compiler picks.

## The sysroots

Both are Debian 12 (bookworm), unpacked with `dpkg-deb -x`, no root needed.

```sh
# amd64
for d in libc6-dev linux-libc-dev libssl-dev libssl3; do
    # take the bookworm amd64 .deb for $d from deb.debian.org
    dpkg-deb -x "$d"*.deb /tmp/sys64
done
printf '#!/bin/sh\nexec gcc --sysroot=/tmp/sys64 "$@"\n' > /tmp/cc64 && chmod +x /tmp/cc64

# arm64
for d in libc6-dev linux-libc-dev libssl-dev libssl3 libc6; do
    # take the bookworm arm64 .deb for $d
    dpkg-deb -x "$d"*.deb /tmp/armsysroot
done
cat > /tmp/cc-arm <<'EOF'
#!/bin/sh
INC=$(aarch64-linux-gnu-gcc -print-file-name=include)
exec aarch64-linux-gnu-gcc --sysroot=/tmp/armsysroot -nostdinc \
  -isystem /tmp/armsysroot/usr/include \
  -isystem /tmp/armsysroot/usr/include/aarch64-linux-gnu \
  -isystem "$INC" "$@"
EOF
chmod +x /tmp/cc-arm
```

`-nostdinc` is not optional for the cross build: the toolchain keeps its own
glibc headers in `/usr/aarch64-linux-gnu/include`, outside any sysroot, and
without `-nostdinc` they win and put glibc 2.38 back.

## The builds

```sh
# amd64: CPU kernels only, which is what the release ships
make clean && make -j"$(nproc)" CC=/tmp/cc64 CUDA=0 VULKAN=0 L0=0 OPENCL=0
cd betterAnusbis && make CC=/tmp/cc64
cd ..

# arm64
make clean && make ARCH=aarch64 CC=/tmp/cc-arm NATIVE= \
    CUDA=0 VULKAN=0 L0=0 OPENCL=0 BUILD=/tmp/arm/obj libanubis_solver.so
cd betterAnusbis && /tmp/cc-arm -O2 -g -Wall -Wextra -pthread -std=gnu17 \
    -I../include -o /tmp/arm/betterAnusbis betterAnusbis.c \
    -L/tmp/armsysroot/usr/lib/aarch64-linux-gnu -L.. \
    -lanubis_solver -lssl -lcrypto -Wl,-rpath,'$ORIGIN'
```

`--sysroot` changes where the compiler looks, not where the linker puts things;
`-Wl,-rpath,'$ORIGIN'` is what lets the pair work from any directory.

## Checking the floor before shipping

```sh
objdump -T betterAnusbis/betterAnusbis | grep -o 'GLIBC_[0-9.]*' | sort -Vu | tail -1
aarch64-linux-gnu-objdump -T /tmp/arm/betterAnusbis | grep -o 'GLIBC_[0-9.]*' | sort -Vu | tail -1
```

Both must say `GLIBC_2.34`. If either says `GLIBC_2.38`, a `__isoc23_*` symbol
got in, which means the headers are the host's and not the sysroot's.

## Running the ARM build without ARM hardware

```sh
# qemu-user-static for the host (amd64), arm64 libc already in the sysroot
curl -O http://deb.debian.org/debian/pool/main/q/qemu/qemu-user-static_*_amd64.deb
dpkg-deb -x qemu-user-static_*_amd64.deb /tmp/qtools

mkdir -p /tmp/armrun/opt/anubis /tmp/armrun/usr/lib
cp -r /tmp/armsysroot/lib /tmp/armrun/
cp -r /tmp/armsysroot/usr/lib/aarch64-linux-gnu /tmp/armrun/usr/lib/
cp /tmp/arm/betterAnusbis libanubis_solver.so /tmp/armrun/opt/anubis/

cd /tmp/armrun/opt/anubis
/tmp/qtools/usr/bin/qemu-aarch64-static -L /tmp/armrun ./betterAnusbis --version
/tmp/qtools/usr/bin/qemu-aarch64-static -L /tmp/armrun ./betterAnusbis \
    --target http://127.0.0.1:9 --listen 127.0.0.1:8713 --difficulty 4
curl -i http://127.0.0.1:8713/     # 200, and a challenge page
```

That is a link check and a start check, not a benchmark: qemu is a translator
and the numbers it produces mean nothing. It does prove the ARM pair loads,
listens and answers, which is what a release artifact has to do.

## Windows (x86-64)

One command, no Windows involved:

```sh
./betterAnusbis/win32/build-windows.sh --deps
```

`--deps` downloads and cross-builds the two libraries the gate needs; leave it
out to reuse a prepared `build/windows/deps/` (or point `OPENSSL_DIR` and
`PCRE2_DIR` at your own trees). Requirements: `gcc-mingw-w64-x86-64-posix`,
`make`, and `curl` or `wget`. Optional: `wine` for the verification step and
`wixl` (the `msitools` + `wixl` packages) for the MSI.

The script builds two things:

- `anubis_solver.dll` from the engine, with `ARCH=none` so the ELF `.s` kernels
  are not linked. The portable C fallbacks are what the Windows release runs;
  SHA-NI/AVX2 dispatch is therefore off, which is why the Windows zip does not
  claim the Linux bytes-per-second numbers.
- `betterAnusbis.exe` from `betterAnusbis.c` against `win32-compat.h`,
  `win32/include/`, the cross-built OpenSSL and PCRE2's POSIX regex wrapper.
  Both libraries are linked statically, so the pair only needs `KERNEL32.dll`
  and `msvcrt.dll` at run time. The DLL is the only other import.

The `.exe` and the `.dll` must ship together; the executable imports
`anubis_solver.dll` by name.

What the Windows build leaves out, on purpose: HTTP/2 and HTTP/3. nghttp2 and
nghttp3 are optional everywhere, the release links neither, so the binary is
HTTP/1.1-only and `--http2`/`--http3` say so at startup. HashX uses the
interpreter: the generated x86-64 code is System V ABI (register file in `rdi`,
`rsi` as scratch), which is not the Windows x64 calling convention. Everything
else — six algorithms, policy file, honeypot, the four stores, TLS with
`--tls-cert`/`--tls-key`, HTTPS origin, metrics, `--healthcheck` — is the same
code and is exercised by the smoke test.

Verifying without Windows:

```sh
./betterAnusbis/win32/build-windows.sh --smoke
```

That asks wine for `--version`, then starts a backend, starts the gate under
wine, fetches a challenge, solves it with the Linux build of the engine and
passes it, asserting the protected page comes back with the cookie. The MSI is
worth checking the same way when it is rebuilt:

```sh
WINEDEBUG=-all wine msiexec /i betterAnusbis-<ver>-x86_64-windows.msi /qn
ls "$HOME/.wine/drive_c/Program Files/betterAnusbis"
WINEDEBUG=-all wine "$HOME/.wine/drive_c/Program Files/betterAnusbis/betterAnusbis.exe" --version
WINEDEBUG=-all wine msiexec /x '{78E93DDB-6152-5CDA-B2B6-8FE765DEBC74}' /qn
```

The MSI installs under `Program Files\betterAnusbis`, appends that directory to
the machine `PATH`, and is a per-machine package (`ProgramFiles64Folder`, x64
summary information from `wixl -a x64`). No shortcuts: this is a command-line
gate, and a Start Menu entry that starts a proxy with no `--target` would be a
trap. The GUIDs in `win32/betterAnusbis.wxs` are fixed on purpose so upgrades
and uninstalls line up; change `UpgradeCode` only when the product identity
changes.

The MSI is not silent-only. It carries the WixUI_Minimal dialogs, so a normal
install opens the license page: the anti-anti-ai mascot on the left, the
project's MIT + attribution text (generated from `LICENSE` at build time) on the
right, and the *I accept* checkbox that enables **Install**. `wixl-data`
supplies that dialog set; the build script copies it into
`build/windows/wixui/`, drops the title font a point, widens `WelcomeEulaDlg`
from 370 to 410 dialog units so "Please read the betterAnusbis License
Agreement" stays on one line, and swaps in
`betterAnusbis/win32/installer/dlgbmp.bmp` as the dialog background. That bitmap
is generated from `mascot/anti-anti-ai.png` by
`betterAnusbis/win32/make-installer-art.sh`; regenerate it only when the mascot
or the dialog size changes. If `wixl-data` is missing the build says so and skips
the MSI rather than failing the exe.

Review the page before shipping: `wine msiexec /i betterAnusbis-<ver>-x86_64-windows.msi`,
accept the license, install, then `wine msiexec /x {78E93DDB-6152-5CDA-B2B6-8FE765DEBC74} /qn`.
The checkbox must enable Install and the license text must scroll; if the page
is blank, `License.rtf` was generated without its closing brace or was picked up
from a stale directory.

The supported floor is Windows 10/11 x86-64. `--bind-network unix` additionally
needs Windows 10 1803 or newer for AF_UNIX sockets; TCP is the normal mode and
has no such requirement.

## What goes on the release

Per Linux architecture: a tarball with both binaries plus LICENSE,
ATTRIBUTION.md and MIGRATE.md, and the two raw files. The x86-64 raw files keep
the canonical names (`betterAnusbis`, `libanubis_solver.so`); the aarch64 ones
carry a suffix, and `libanubis_solver-aarch64.so` has to be renamed to
`libanubis_solver.so` next to the binary, because that is the name in
`DT_NEEDED`.

For Windows: `betterAnusbis-<ver>-x86_64-windows.zip` (the exe, the DLL,
`README-WINDOWS.txt`, LICENSE, ATTRIBUTION.md, MIGRATE.md),
`betterAnusbis-<ver>-x86_64-windows.msi`, and the two raw files
`betterAnusbis.exe` and `anubis_solver.dll`. The raw Windows pair keeps its
canonical names and, unlike the Linux pair, must stay side by side: the exe
imports the DLL by name.

The GPU backends are compiled per machine (CUDA, Level Zero, Vulkan, OpenCL are
dlopen-based and need local drivers and headers), so the release build is CPU
only, and says so — on both platforms.

## PyPI

The distribution is `libanubis-solver` (`pip install libanubis-solver`); the
import name stays `anubis_solver`. The name `anubis-solver` on PyPI is an
unrelated pure-Python project by another author, so it cannot be used, and
installing both puts two different `anubis_solver.py` files in one
site-packages - pick one.

Two artifacts, for two different problems:

| artifact | who it is for | what it does |
|---|---|---|
| `libanubis_solver-<v>.tar.gz` | any Linux with a C compiler | runs `make` at install time (CPU kernels only) |
| `libanubis_solver-<v>-py3-none-manylinux_2_XX_x86_64.whl` | no compiler needed | ships `libanubis_solver.so` inside `_anubis_solver_native/` |

`setup.py` builds the object in a **copy** of the tree with
`CUDA=0 VULKAN=0 L0=0 OPENCL=0`, so a developer's last `make` cannot leak
whatever backends they had enabled into the wheel (make does not track flag
changes). The GPU and TPU backends are `dlopen`ed, so a CPU-only build is the
right wheel: it still uses a GPU or TPU when the runtime is there.

```sh
# from a checkout, never from a directory where `python -m build` would
# shadow the repo's own build/ object directory
rm -rf dist
ANUBIS_WHEEL_PLAT=manylinux_2_38_x86_64 \
    /tmp/buildenv/bin/python -m build --outdir "$PWD/dist" "$PWD"

twine check dist/*

# TestPyPI first, always
twine upload --repository testpypi dist/*
python3 -m pip install --index-url https://test.pypi.org/simple/ \
        --extra-index-url https://pypi.org/simple libanubis-solver

# then the real one
twine upload dist/*
```

`TWINE_USERNAME=__token__` and `TWINE_PASSWORD=pypi-...` (or a `~/.pypirc`).
An API token scoped to the `libanubis-solver` project is better than an account
token; TestPyPI needs its own.

Two caveats before the first upload:

1. **The platform tag must be honest.** A wheel built on this host needs glibc
   2.38, so it is named `manylinux_2_38_x86_64` and pip refuses it on anything
   older (Debian 13+/Ubuntu 24.04+). For a wider wheel, build against the
   bookworm sysroots above and pass `ANUBIS_WHEEL_PLAT=manylinux_2_34_x86_64`.
   `linux_x86_64` must not be published: it installs everywhere and then fails
   at `ctypes.CDLL`.
2. **OpenSSL 3 is a runtime dependency.** The object links `libssl.so.3` and
   `libcrypto.so.3`; they are not in the wheel. Debian 12+/Ubuntu 22.04+ and
   current Fedora have them. `auditwheel show dist/*.whl` lists them if in
   doubt.

The version lives in five places, and they have to agree or `--version` lies
depending on which binary you ask:

| where | what |
|---|---|
| `anubis_solver.py` | `__version__` |
| `pyproject.toml` | `project.version` |
| `src/core/anubis_solver.c` | `anubis_solver_version()` and `anubis_solver_codename()` |
| `betterAnusbis/betterAnusbis.c` | `VERSION` and `CODENAME` (the Windows/MSI build reads `VERSION` from here) |
| `src/mcp/anubis_mcp.c` | `SERVER_VERSION` and its codename fallback |

Plus the examples that are meant to show the current build: the README, MIGRATE,
BEGINNER, `docs/mcp.md`, `docs/api-service.md`, and `version=` in
`betterAnusbis/test_parity.py`. Then `git tag v<version>` and push the tag.

### Publishing without a token

`.github/workflows/pypi.yml` builds the sdist and a `manylinux_2_35` wheel on
an ubuntu-22.04 runner, smoke-tests the wheel (`solve` a sha256 challenge), and
uploads through PyPI's trusted publishing (OIDC): no API token is stored
anywhere. It needs a one-time *pending publisher* on PyPI (project name
`libanubis-solver`, this repository, workflow `pypi.yml`, environment `pypi`)
and the same on TestPyPI for `workflow_dispatch` runs.

Push a tag (`git tag v2.50 && git push origin v2.50`) or run the workflow
manually with `test: true` first.
