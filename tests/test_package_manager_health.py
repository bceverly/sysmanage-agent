# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Package manager needs repair (2026-11-13): eight production hosts were
left with dpkg interrupted, and every update sent to them failed while they
looked healthy."""

# pylint: disable=protected-access

from src.sysmanage_agent.collection import package_manager_health as health


class Tools:
    def __init__(self, have, answers=None):
        self.have = set(have)
        self.answers = answers or {}
        self.ran = []

    def which(self, name):
        return f"/usr/bin/{name}" if name in self.have else None

    def run(self, argv, _timeout):
        self.ran.append(argv)
        bare = argv[2:] if argv[:2] == ["sudo", "-n"] else argv
        return self.answers.get(tuple(bare), (0, ""))


def _probe(tools, system="Linux", updates=()):
    return {"which": tools.which, "listdir": lambda _p: list(updates), "system": system}


def test_an_interrupted_dpkg_needs_repair():
    tools = Tools({"dpkg"})
    found = health.check(run=tools.run, **_probe(tools, updates=["0001"]))
    assert found == {"manager": "dpkg", "needs_repair": True,
                     "reason": "dpkg was interrupted", "repairable": True}  # fmt: skip


def test_half_installed_packages_need_repair_and_a_clean_dpkg_does_not():
    audit = ("dpkg", "--audit")
    broken = Tools(
        {"dpkg"},
        {audit: (0, "The following packages are only half configured:\n snapd\n")},
    )
    found = health.check(run=broken.run, **_probe(broken))
    assert found["needs_repair"] and "half configured" in found["reason"]
    clean = Tools({"dpkg"})
    assert health.check(run=clean.run, **_probe(clean))["needs_repair"] is False


def test_dnf_problems_are_reported_but_never_repaired():
    tools = Tools(
        {"dnf"}, {("dnf", "-q", "check"): (1, "foo-1.0 has missing requires of bar\n")}
    )
    found = health.check(run=tools.run, **_probe(tools))
    assert found["needs_repair"] and found["repairable"] is False
    result = health.repair(run=tools.run, **_probe(tools))
    assert result["success"] is False and result["reason"] == "not_repairable"
    assert not any("sudo" in argv for argv in tools.ran)


def test_freebsd_missing_dependencies():
    tools = Tools(
        {"pkg"},
        {
            ("pkg", "check", "-d", "-n"): (
                1,
                "curl has a missing dependency: libnghttp2\n",
            )
        },
    )
    found = health.check(run=tools.run, **_probe(tools, system="FreeBSD"))
    assert found["manager"] == "pkg" and found["needs_repair"]


def test_repair_runs_the_standard_fix_then_checks_again(monkeypatch):
    monkeypatch.setattr(health.os, "geteuid", lambda: 1000, raising=False)
    state = {"updates": ["0001"]}
    tools = Tools({"dpkg"})

    def run(argv, timeout):
        if argv[-2:] == ["--configure", "-a"]:
            state["updates"] = []
        return tools.run(argv, timeout)

    probe = {
        "which": tools.which,
        "listdir": lambda _p: state["updates"],
        "system": "Linux",
    }
    result = health.repair(run=run, **probe)
    assert result["success"] and result["health"]["needs_repair"] is False
    assert ["sudo", "-n", "dpkg", "--configure", "-a"] in tools.ran
    assert ["sudo", "-n", "apt-get", "install", "-f", "-y"] in tools.ran


def test_a_failed_repair_says_so_with_its_output(monkeypatch):
    monkeypatch.setattr(health.os, "geteuid", lambda: 1000, raising=False)
    tools = Tools(
        {"dpkg"},
        {("dpkg", "--configure", "-a"): (1, "dpkg: error processing package snapd\n")},
    )
    result = health.repair(run=tools.run, **_probe(tools, updates=["0001"]))
    assert result["success"] is False and result["reason"] == "repair_failed"
    assert "error processing package snapd" in result["output"]


def test_nothing_is_checked_where_there_is_no_manager_it_knows():
    tools = Tools(set())
    assert (
        health.check(run=tools.run, **_probe(tools, system="Darwin"))["manager"] is None
    )
    assert health.unavailable_reason(system="Windows") == "wrong_platform"
    assert health.unavailable_reason(system="Linux") is None


def test_the_sudoers_grant_exactly_the_repair_commands():
    from pathlib import Path  # pylint: disable=import-outside-toplevel

    root = Path(__file__).resolve().parents[1] / "installer"
    assert (
        "NOPASSWD: /usr/bin/dpkg --configure -a\n"
        in (root / "ubuntu" / "sysmanage-agent.sudoers").read_text()
    )
    freebsd = (root / "freebsd" / "sysmanage-agent.sudoers").read_text()
    assert "NOPASSWD: /usr/local/sbin/pkg check -d -y\n" in freebsd
