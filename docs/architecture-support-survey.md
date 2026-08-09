# Agent architecture & platform support survey

**Date:** 2026-08-09  ·  **Agent version surveyed:** 3.5.1.8

Measured against live package metadata, not inferred. Every table below came
from querying the actual repository indexes on the date above; the method is
recorded at the end so it can be re-run when it goes stale.

The question this answers: **if we ship the agent on s390x, ppc64le, riscv64 —
and on Intel macOS, the BSDs, and mobile — what capabilities would be
unavailable because a package isn't ported there?**

---

## Summary

| platform | verdict |
|---|---|
| Linux — Debian/Ubuntu, Alpine | **Full capability on all 5 arches**, riscv64 included |
| Linux — EL9 (RPM/COPR) | Full on x86_64/aarch64/ppc64le/s390x; **riscv64 impossible** |
| FreeBSD | amd64/aarch64 solid; ppc64* Tier-2; **no riscv64, no s390x packages** |
| OpenBSD / NetBSD | broad arch coverage incl. riscv64; container ops unavailable (OS-level) |
| macOS Apple Silicon | full |
| macOS Intel | **`cryptography` has no Intel wheel from 49.0.0 — fixed in the Homebrew formula** |
| iOS / Android | **inventory only** — cannot run the agent as designed |

**The headline: no capability is lost to architecture on Linux.** The blockers
found were in *our packaging*, not in the distros.

---

## 1. PyPI wheels — why this is the wrong lens

Agent runtime dependencies, latest releases, wheel availability:

| package | pure Python | x86_64 | aarch64 | ppc64le | s390x | riscv64 |
|---|---|---|---|---|---|---|
| websockets, aiofiles, defusedxml, SQLAlchemy, alembic, Mako, idna | yes | — any arch — |
| aiohttp | no | ✓ | ✓ | ✓ | ✓ | ✓ |
| PyYAML | no | ✓ | ✓ | ✗ | ✓ | ✗ |
| cryptography | no | ✓ | ✓ | ✓ | ✗ | ✗ |
| psutil | no | ✓ | ✓ | ✗ | ✗ | ✗ |
| bcrypt | no | ✓ | ✓ | ✗ | ✗ | ✗ |

All four gaps are **core** dependencies — config parsing, TLS, process
inventory, password hashing. A missing one doesn't produce a reduced agent; it
produces an agent that won't start.

**But every distro packages them.** Wheels only matter where our packaging
chooses to use them, which is the actual finding in §2.

## 2. Linux distributions

### Alpine v3.21 — all 12 dependencies plus `qemu-system-*` and `libvirt-client`

| x86_64 | aarch64 | ppc64le | s390x | riscv64 |
|---|---|---|---|---|
| ✓ | ✓ | ✓ | ✓ | ✓ |

### Debian trixie — all 12, plus `qemu-utils`, `libvirt-clients`, `virtinst`, `genisoimage`, `xorriso`, `rustc`, `cargo`

Zero gaps on amd64, arm64, ppc64el, s390x, **riscv64**.

### EL9 — complete, but split across repos

| repo | supplies |
|---|---|
| CS9 BaseOS | `python3-cryptography`, `python3-pyyaml`, `python3-idna` |
| CS9 AppStream | `python3-psutil`, `-websockets`, `-sqlalchemy`, `-alembic`, `-mako`, `libvirt-client`, `virt-install`, `qemu-img`, `xorriso`, `rust`, `cargo` |
| **EPEL9** | `python3-bcrypt`, `python3-aiofiles`, `python3-defusedxml`, `python3-aiohttp`, `genisoimage` |

**An EL9 RPM built on distro dependencies must require EPEL.** Arch trees exist
for x86_64, aarch64, ppc64le, s390x — riscv64 does not exist for EL9 at all.

### Fedora 44

All packages present. Arch publication: x86_64/aarch64 primary,
ppc64le/s390x in fedora-secondary, **riscv64 not published** (COPR chroots
exist for f43/f44, but there is no release repo for users).

### COPR chroots available

```
epel-9      x86_64  aarch64  ppc64le  s390x
epel-10     x86_64  aarch64  ppc64le  s390x
fedora-43   x86_64  aarch64  ppc64le  s390x  riscv64  i386
fedora-44   x86_64  aarch64  ppc64le  s390x  riscv64  i386
```

### The three blockers are ours

1. **RPM vendors manylinux wheels** —
   `pip3 download --only-binary=:all: --platform manylinux2014_<arch>` fails for
   four packages on s390x/ppc64le. The distro RPMs exist; we bypass them.
2. **DEB pip-installs into a venv** — `Depends:` carries `gcc`, `libffi-dev`,
   `libssl-dev` but **not Rust**, and `cryptography`/`bcrypt` need a Rust
   toolchain to build from source. Debian ships `rustc`/`cargo` on all five
   arches; either add them or depend on `python3-*` and build nothing.
3. **Alpine `APKBUILD` under-declares** — it lists 6 of 12 runtime deps.
   `Mako` and `idna` arrive transitively; **`psutil`, `bcrypt`, `aiofiles`,
   `defusedxml` do not**. Same defect class as the FreeBSD port's missing
   `RUN_DEPENDS`, and it would surface as an ImportError at first use.

## 3. BSD

Binary package trees that exist today:

| OS | architectures |
|---|---|
| FreeBSD 14/15 | amd64, aarch64, armv6, armv7, i386, powerpc, powerpc64, powerpc64le — **no riscv64, no s390x** |
| OpenBSD 7.9 | amd64, aarch64, arm, i386, mips64, powerpc, powerpc64, **riscv64**, sparc64 |
| NetBSD | ~45 arches incl. amd64, aarch64, **riscv64**, powerpc, sparc64, vax |

Capability gaps on BSD are **OS-level, not architecture-level**:

- **containers** — no Docker/LXD; the container capability group is unavailable
- `ubuntu_pro`, `fips` — not applicable (OS-exclusive, not a portability gap)
- virtualization *is* available: bhyve (FreeBSD), vmm (OpenBSD), and the agent
  supports both

**Not verified:** per-arch package *completeness* on the BSDs. Arch trees exist;
whether every dependency is built in each was not checked, and FreeBSD's Tier-2
arches can lag Tier 1.

## 4. macOS

| package | Intel (x86_64) | Apple Silicon (arm64) |
|---|---|---|
| psutil, bcrypt, PyYAML, aiohttp | ✓ | ✓ |
| **cryptography** | **✗ from 49.0.0** | ✓ |

`cryptography` macOS wheel tags by release:

| version | tags | Intel? |
|---|---|---|
| 47.0.0 | `macosx_10_9_universal2`, `macosx_11_0_arm64` | yes |
| 48.0.0 | `macosx_10_9_universal2`, `macosx_11_0_arm64` | yes |
| **48.0.1** | `macosx_10_9_universal2`, `macosx_11_0_arm64` | yes |
| 49.0.0 | `macosx_11_0_arm64` | **no** |
| 50.0.0 | `macosx_11_0_arm64` | **no** |

`requirements-prod.txt` asks for `cryptography>=48.0.1` (that floor is the
CVE-fixed line), which on an Intel Mac resolved to 50.0.0, found no wheel, and
fell back to a source build needing Rust and OpenSSL headers that a plain
`brew install` does not provide.

**FIXED 2026-08-09** in `packaging/homebrew/sysmanage-agent.rb`: the formula
pins `cryptography>=48.0.1,<49` before resolving, but only when
`OS.mac? && Hardware::CPU.intel?`. Deliberately fixed there rather than in
`requirements-prod.txt`, because agent runtime deps must use bare floors with no
environment markers — COPR's `pip download --python-version` evaluates markers
against the build host. 48.x carries the same CVE fixes as the floor, so this is
a wheel-availability pin, not a security regression. Remove it when
`cryptography` ships Intel wheels again, or when Intel Macs are dropped.

## 5. iOS / Android — the genuine limiting case

Neither can run the agent as designed. CPython supports both (PEP 730 / PEP 738),
but:

- no persistent background daemon (iOS background windows, Android Doze)
- no `subprocess` to system tools — which is how ~20 of the 22 capability
  groups work
- no package manager, no root, sandboxed filesystem

Realistic capability: **`inventory` only**, and a reduced form of it via
platform APIs rather than shell commands. This matches the Phase 22 companion
app already described in the ROADMAP as "reports inventory, executes nothing" —
and it is the one place a genuinely trimmed agent build is unavoidable rather
than optional.

## 6. What this means for the "limited capability" feature

The capability advertisement mechanism (Phase 19) is complete: the agent derives
its report from its live handler map, the server ingests and normalizes it,
dispatch is gated on it, and the UI shows it.

**On the architectures surveyed here it will report every host as "Full",** and
that is the correct answer — nothing is lost to architecture on Linux, and the
BSD gaps are OS-level rather than portability gaps. The feature earns its keep
on mobile (§5) and on any future target where a native library genuinely has no
build.

Keep it, keep the tests green, and expect the badge to stay quiet until a
trimmed build actually ships.

---

## Method

Re-runnable. All of it hits public metadata endpoints:

| what | source |
|---|---|
| PyPI wheels | `https://pypi.org/pypi/<pkg>/json`, wheel filename tags |
| Alpine | `https://dl-cdn.alpinelinux.org/alpine/v3.21/{main,community}/<arch>/APKINDEX.tar.gz` |
| Debian | `https://api.ftp-master.debian.org/madison?package=<pkg>&f=json` |
| Fedora | `https://mdapi.fedoraproject.org/f44/pkg/<pkg>` + release repo layout |
| EL9 | CS9 `BaseOS`/`AppStream`/`CRB` + EPEL9 `repodata/primary` (EPEL's is **XZ**, not gzip) |
| COPR | `https://copr.fedorainfracloud.org/api_3/mock-chroots/list` |
| BSD | package-tree directory listings on `pkg.freebsd.org`, `cdn.openbsd.org`, `cdn.NetBSD.org` |

Worth re-running when: a new arch is proposed, `cryptography` changes its macOS
wheel policy, or EL10 replaces EL9 as the RPM target.
