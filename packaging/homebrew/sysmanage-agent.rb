# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

# sysmanage-agent Homebrew formula — Phase 11.8 stub.
#
# This formula lives in the sysmanage-agent repo *pending* the user
# creating the ``bceverly/homebrew-tap`` GitHub repository.  Once the
# tap exists, copy this file to:
#     <tap-root>/Formula/sysmanage-agent.rb
# (or, for newer Homebrew, just ``sysmanage-agent.rb`` at the tap root)
# and ``brew install bceverly/tap/sysmanage-agent`` Just Works for
# every macOS + Linuxbrew client globally.
#
# *** USER ACTION REQUIRED ***
#
# Per-release update workflow (until the build-and-release.yml
# ``homebrew-tap`` job is enabled — see the DRY-RUN-only job we
# landed alongside this stub):
#
#   1. Bump ``url`` to point at the new release tarball.
#   2. Re-compute ``sha256`` against the tarball:
#         shasum -a 256 sysmanage-agent-X.Y.Z.tar.gz
#   3. Bump ``version`` to match.
#   4. ``cd ~/path/to/homebrew-tap``
#      ``cp <here>/sysmanage-agent.rb Formula/sysmanage-agent.rb``
#      ``git commit -am "sysmanage-agent X.Y.Z"``
#      ``git push``
#   5. End users get the new release via ``brew upgrade`` which finally
#      makes the in-app "Update Agent" button work on macOS.
#
# Once the tap repo exists, the build-and-release.yml ``homebrew-tap``
# job (currently DRY-RUN-only behind a workflow_dispatch flag) can be
# flipped to actually push.  The job is structured so flipping
# ``dry_run`` to ``false`` and wiring ``HOMEBREW_TAP_DEPLOY_KEY`` into
# the repo secrets is the only change needed.
#
# Linuxbrew is supported by the same formula; ``depends_on :linux``
# is not used — pure-Python deps run on both.

class SysmanageAgent < Formula
  desc "Cross-platform system management agent for SysManage"
  homepage "https://github.com/bceverly/sysmanage-agent"
  url "https://github.com/bceverly/sysmanage-agent/archive/refs/tags/v0.0.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "AGPL-3.0-or-later"
  version "0.0.0"

  depends_on "python@3.12"

  # Runtime resources are vendored at build time via
  # ``scripts/update-requirements-prod.py`` in the agent repo —
  # the tarball ships with a frozen requirements-prod.txt so the
  # ``virtualenv_install_with_resources`` block below is fully
  # offline-deterministic.

  def install
    venv = virtualenv_create(libexec, "python3.12")

    # INTEL MACS: pin cryptography below 49 before anything else resolves it.
    #
    # cryptography dropped x86_64 macOS wheels at 49.0.0 — 48.0.1 still ships
    # ``macosx_10_9_universal2``, 49.0.0 and 50.0.0 are ``macosx_11_0_arm64``
    # ONLY (verified against PyPI 2026-08-09).  requirements-prod.txt asks for
    # ``cryptography>=48.0.1`` (that floor is the CVE-fixed line), which on an
    # Intel Mac resolves to 50.0.0, finds no wheel, and falls back to building
    # from source — needing a Rust toolchain and OpenSSL headers that a plain
    # ``brew install`` does not provide.  Apple Silicon is unaffected.
    #
    # Fixed HERE rather than in requirements-prod.txt on purpose: agent runtime
    # deps must use bare floors with no environment markers, because COPR's
    # ``pip download --python-version`` evaluates markers against the build
    # host and silently drops or mis-resolves them.  Confining the pin to the
    # macOS packaging keeps that rule intact.
    #
    # 48.x carries the same CVE fixes as the floor, so this is a wheel-
    # availability pin, not a security regression.  Remove it when cryptography
    # ships Intel wheels again, or when Intel Macs are dropped.
    if OS.mac? && Hardware::CPU.intel?
      venv.pip_install "cryptography>=48.0.1,<49"
    end

    venv.pip_install_and_link buildpath
    (etc/"sysmanage-agent").mkpath
    (var/"lib/sysmanage-agent").mkpath
    (var/"log/sysmanage-agent").mkpath
    # Install the example config.  The service block points
    # SYSMANAGE_CONFIG at this exact path, so it is read where it lands —
    # no relocation needed.  Don't overwrite if present.
    config_dest = etc/"sysmanage-agent/sysmanage-agent.yaml"
    cp "sysmanage-agent-system.yaml", config_dest unless config_dest.exist?
  end

  service do
    run [opt_bin/"sysmanage-agent"]
    # The agent parses NO command-line arguments and its built-in search order
    # is /etc/sysmanage-agent.yaml then ./sysmanage-agent.yaml — neither of
    # which is where this formula installs the config (HOMEBREW_PREFIX/etc).
    # Without this the service starts and dies with "Configuration file not
    # found", and the comment above telling users to relocate to
    # /usr/local/etc was wrong: that path is not searched either.
    # SYSMANAGE_CONFIG is the override main.py honours; absolute paths are
    # used verbatim.
    environment_variables SYSMANAGE_CONFIG: etc/"sysmanage-agent/sysmanage-agent.yaml"
    keep_alive true
    log_path var/"log/sysmanage-agent/agent.log"
    error_log_path var/"log/sysmanage-agent/agent.err.log"
    working_dir var/"lib/sysmanage-agent"
  end

  test do
    assert_match "sysmanage-agent", shell_output("#{bin}/sysmanage-agent --version")
  end
end
