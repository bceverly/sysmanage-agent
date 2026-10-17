# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""An SSDP M-SEARCH says what the sender is LOOKING FOR, not what it is.

Read as identity, a Windows laptop searching for its router became "network
equipment" and Chrome searching for cast targets made a laptop a "media
player" (2026-10-17).  NOTIFY and 200 replies still describe the sender."""

from src.sysmanage_agent.collection import network_discovery_collection as ndc


def _msg(*lines):
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


WINDOWS_IGD_SEARCH = _msg(
    "M-SEARCH * HTTP/1.1",
    "HOST: 239.255.255.250:1900",
    'MAN: "ssdp:discover"',
    "MX: 2",
    "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1",
)
CHROME_DIAL_SEARCH = _msg(
    "M-SEARCH * HTTP/1.1",
    "HOST: 239.255.255.250:1900",
    'MAN: "ssdp:discover"',
    "MX: 1",
    "ST: urn:dial-multiscreen-org:service:dial:1",
    "USER-AGENT: Google Chrome/130.0 Linux",
)
ROKU_NOTIFY = _msg(
    "NOTIFY * HTTP/1.1",
    "HOST: 239.255.255.250:1900",
    "NT: roku:ecp",
    "NTS: ssdp:alive",
    "USN: uuid:roku:ecp:X00000000000",
    "SERVER: Roku/12.5.0 UPnP/1.0 Roku/12.5.0",
)
ROUTER_REPLY = _msg(
    "HTTP/1.1 200 OK",
    "CACHE-CONTROL: max-age=120",
    "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "USN: uuid:0000::urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "SERVER: FreeBSD/15.0 UPnP/1.1 MiniUPnPd/2.3.7",
)


def test_a_windows_router_search_is_not_identity():
    identity, searches = ndc.ssdp_parse(WINDOWS_IGD_SEARCH)
    assert identity == []
    assert searches == ["urn:schemas-upnp-org:device:InternetGatewayDevice:1"]


def test_a_chrome_dial_search_is_not_identity():
    identity, searches = ndc.ssdp_parse(CHROME_DIAL_SEARCH)
    assert identity == []
    assert searches == ["urn:dial-multiscreen-org:service:dial:1"]


def test_a_notify_still_describes_the_sender():
    identity, searches = ndc.ssdp_parse(ROKU_NOTIFY)
    assert "NT: roku:ecp" in identity
    assert any(line.startswith("SERVER: Roku") for line in identity)
    assert searches == []


def test_a_reply_marks_its_st_as_identity():
    identity, searches = ndc.ssdp_parse(ROUTER_REPLY)
    assert "RST: urn:schemas-upnp-org:device:InternetGatewayDevice:1" in identity
    assert not any(line.startswith("ST:") for line in identity)
    assert searches == []


def test_the_report_carries_searches_apart():
    sink = ndc._Accumulator()
    identity, searches = ndc.ssdp_parse(WINDOWS_IGD_SEARCH)
    sink.note("ip:192.168.4.193", None, "192.168.4.193", None, "ssdp",
              ssdp=identity, searches=searches)  # fmt: skip
    devices, _ = sink.drain()
    observation = ndc._observation(devices["ip:192.168.4.193"])
    assert observation["evidence"]["ssdp"] == []
    assert observation["evidence"]["ssdp_searches"] == [
        "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
    ]
