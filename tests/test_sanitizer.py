"""Sanitized downloads, end to end, checked with the real tshark.

A sanitizer is judged by what it leaves behind, so the assertions here read the
sanitized output back through tshark rather than trusting the sanitizer's own
account of what it did:

  * **Secrets are gone** from every place tshark can find them -- including a
    retransmitted copy, which tshark does not dissect by default.
  * **The file is still a good capture**: same packets, same lengths, and
    checksums tshark itself validates as correct.
  * **Mappings line up**: an address in a DNS answer gets the same stand-in as
    the same address in an IP header, and a second download is identical.
  * **What was not asked for is untouched**, and what cannot be sanitized is
    refused rather than passed through.
  * **The routes** keep the rules every other download follows: HTTPS only,
    your own capture only, and a summary handed out once.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import stat
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend import main
from backend.auth import create_session_token
from backend.crypto import Cryptor
from backend.models import CaptureInfo, CaptureStatus
from backend.pcapsource import BytesSource
from backend.rekey import rekey_file
from backend.sanitizer import (
    INSTALL_SECRET_NAME,
    FilteredSource,
    SanitizeError,
    SanitizeOptions,
    SanitizeSummary,
    capture_key,
    check_capture,
    install_secret,
    stream_sanitized_pcap,
)
from tests.packet_builders import (
    dns_query,
    dns_response_a,
    ethernet,
    ip4,
    ipv4,
    mac,
    pcap,
    read_pcap,
    sll2,
    snmp_get,
    tcp,
    tls_client_hello,
    udp,
)

HAS_TSHARK = shutil.which("tshark") is not None
needs_tshark = pytest.mark.skipif(not HAS_TSHARK, reason="tshark is not installed in this environment")

KEY = bytes(range(64))
CLIENT, SERVER, RESOLVER = ip4("192.168.1.10"), ip4("93.184.216.34"), ip4("8.8.8.8")
CLIENT_MAC, ROUTER_MAC = mac("a4:bb:6d:01:02:03"), mac("00:11:22:33:44:55")


def _eth_ipv4_tcp(src, dst, sport, dport, payload, seq=1) -> bytes:
    return ethernet(ROUTER_MAC, CLIENT_MAC, 0x0800, ipv4(src, dst, 6, tcp(src, dst, sport, dport, payload, seq=seq)))


def _eth_ipv4_udp(src, dst, sport, dport, payload) -> bytes:
    return ethernet(ROUTER_MAC, CLIENT_MAC, 0x0800, ipv4(src, dst, 17, udp(src, dst, sport, dport, payload)))


HTTP_WITH_AUTH = (
    b"GET /private HTTP/1.1\r\nHost: intranet.example.com\r\n"
    b"Authorization: Basic YWxpY2U6aHVudGVyMg==\r\n"
    b"Cookie: session=0123456789abcdef; theme=dark\r\n\r\n"
)


def _sanitize(frames: list[bytes], linktype: int = 1, key: bytes = KEY, **options) -> tuple[bytes, dict]:
    data = pcap(frames, linktype=linktype)
    summary = SanitizeSummary()

    async def run():
        out = bytearray()
        async for chunk in stream_sanitized_pcap(BytesSource(data, len(data)), key, SanitizeOptions(**options), summary):
            out += chunk
        return bytes(out)

    return asyncio.run(run()), summary.as_dict()


def _tshark_fields(data: bytes, tmp_path: Path, *fields: str, display_filter: str = "") -> list[list[str]]:
    path = tmp_path / f"{uuid.uuid4().hex}.pcap"
    path.write_bytes(data)
    cmd = [
        "tshark", "-r", str(path), "-n",
        "-o", "tcp.analyze_sequence_numbers:FALSE",
        "-o", "ip.check_checksum:TRUE", "-o", "tcp.check_checksum:TRUE", "-o", "udp.check_checksum:TRUE",
        "-T", "fields", "-E", "separator=\t", "-E", "occurrence=a", "-E", "aggregator=,",
    ]
    for name in fields:
        cmd += ["-e", name]
    if display_filter:
        cmd += ["-Y", display_filter]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return [line.split("\t") for line in result.stdout.splitlines()]


def _assert_checksums_good(data: bytes, tmp_path: Path) -> None:
    bad = _tshark_fields(
        data, tmp_path, "frame.number",
        display_filter="ip.checksum.status == 0 || tcp.checksum.status == 0 || udp.checksum.status == 0",
    )
    assert bad == []


# --- what gets replaced ---------------------------------------------------------


@needs_tshark
def test_credentials_are_masked_and_the_capture_stays_valid(tmp_path):
    out, summary = _sanitize([_eth_ipv4_tcp(CLIENT, SERVER, 50000, 80, HTTP_WITH_AUTH)])
    rows = _tshark_fields(out, tmp_path, "http.authorization", "http.cookie", "http.host")
    authorization, cookie, host = rows[0]
    assert authorization == "Basic " + "*" * len("YWxpY2U6aHVudGVyMg==")
    assert cookie == "session=****************; theme=****"
    assert host == "intranet.example.com"  # hostnames were not ticked
    assert summary["masked"]["credentials"] == 3
    assert b"hunter2" not in out and b"YWxpY2U6aHVudGVyMg" not in out
    _assert_checksums_good(out, tmp_path)


@needs_tshark
def test_a_retransmitted_copy_is_masked_too(tmp_path):
    """tshark does not hand a retransmitted segment to HTTP by default, so it
    would never report the Authorization header in the copy."""
    frame = _eth_ipv4_tcp(CLIENT, SERVER, 50000, 80, HTTP_WITH_AUTH)
    out, summary = _sanitize([frame, frame, frame])
    assert summary["masked"]["credentials"] == 9
    assert b"YWxpY2U6aHVudGVyMg" not in out


@needs_tshark
def test_nothing_changes_size_and_every_packet_is_kept(tmp_path):
    frames = [
        _eth_ipv4_tcp(CLIENT, SERVER, 50000, 80, HTTP_WITH_AUTH),
        _eth_ipv4_udp(RESOLVER, CLIENT, 53, 40000, dns_response_a("intranet.example.com", "93.184.216.34")),
    ]
    out, _ = _sanitize(frames, hostnames=True, usernames=True)
    original = read_pcap(pcap(frames))
    sanitized = read_pcap(out)
    assert [(i, o) for i, o, _ in sanitized] == [(i, o) for i, o, _ in original]
    assert len(out) == len(pcap(frames))


@needs_tshark
def test_addresses_are_replaced_consistently_across_headers_and_dns(tmp_path):
    frames = [
        _eth_ipv4_udp(RESOLVER, CLIENT, 53, 40000, dns_response_a("www.example.com", "93.184.216.34")),
        _eth_ipv4_tcp(CLIENT, SERVER, 50000, 443, b""),
    ]
    out, summary = _sanitize(frames, credentials=False)
    dns_row, tcp_row = _tshark_fields(out, tmp_path, "ip.src", "ip.dst", "dns.a", "eth.src")
    answer = dns_row[2]
    assert answer != "93.184.216.34"
    assert tcp_row[1] == answer            # the same server, the same stand-in
    assert dns_row[1] == tcp_row[0]        # the same client, the same stand-in
    assert dns_row[3] != "a4:bb:6d:01:02:03"
    assert summary["addresses"] == {"ipv4": 3, "ipv6": 0, "mac": 2}
    _assert_checksums_good(out, tmp_path)


@needs_tshark
def test_a_second_download_is_identical_and_another_key_is_not(tmp_path):
    frames = [_eth_ipv4_tcp(CLIENT, SERVER, 50000, 80, HTTP_WITH_AUTH)]
    first, _ = _sanitize(frames, hostnames=True)
    second, _ = _sanitize(frames, hostnames=True)
    other, _ = _sanitize(frames, key=bytes(reversed(KEY)), hostnames=True)
    assert first == second
    assert first != other


@needs_tshark
def test_hostnames_are_replaced_only_when_ticked(tmp_path):
    frames = [
        _eth_ipv4_udp(CLIENT, RESOLVER, 40000, 53, dns_query("fileserver.corp.example.com")),
        _eth_ipv4_tcp(CLIENT, SERVER, 50000, 443, tls_client_hello("fileserver.corp.example.com")),
    ]
    untouched, _ = _sanitize(frames)
    names = _tshark_fields(untouched, tmp_path, "dns.qry.name", "tls.handshake.extensions_server_name")
    assert names[0][0] == "fileserver.corp.example.com"
    assert names[1][1] == "fileserver.corp.example.com"

    out, summary = _sanitize(frames, hostnames=True)
    names = _tshark_fields(out, tmp_path, "dns.qry.name", "tls.handshake.extensions_server_name")
    dns_name, sni = names[0][0], names[1][1]
    assert dns_name.endswith(".com") and dns_name != "fileserver.corp.example.com"
    assert sni == dns_name                  # one host, one stand-in, wherever it appears
    assert len(dns_name) == len("fileserver.corp.example.com")
    assert summary["masked"]["hostnames"] == 2
    assert b"fileserver" not in out


@needs_tshark
def test_a_reverse_lookup_goes_with_the_ip_option(tmp_path):
    """in-addr.arpa names are addresses written as names."""
    frames = [_eth_ipv4_udp(CLIENT, RESOLVER, 40000, 53, dns_query("34.216.184.93.in-addr.arpa", qtype=12))]
    out, summary = _sanitize(frames)
    name = _tshark_fields(out, tmp_path, "dns.qry.name")[0][0]
    assert name.endswith(".in-addr.arpa") and not name.startswith("34.216.184.93")
    assert summary["masked"]["reverse_dns_names"] == 1

    kept, _ = _sanitize(frames, ips=False)
    assert _tshark_fields(kept, tmp_path, "dns.qry.name")[0][0] == "34.216.184.93.in-addr.arpa"


@needs_tshark
def test_ftp_password_and_username_follow_their_own_options(tmp_path):
    frames = [
        _eth_ipv4_tcp(CLIENT, SERVER, 50000, 21, b"USER alice\r\n", seq=1),
        _eth_ipv4_tcp(CLIENT, SERVER, 50000, 21, b"PASS hunter2\r\n", seq=13),
    ]
    out, _ = _sanitize(frames)
    rows = _tshark_fields(out, tmp_path, "ftp.request.command", "ftp.request.arg")
    assert rows[0] == ["USER", "alice"]
    assert rows[1] == ["PASS", "*******"]

    out, summary = _sanitize(frames, usernames=True)
    rows = _tshark_fields(out, tmp_path, "ftp.request.command", "ftp.request.arg")
    assert rows[0][1] != "alice" and len(rows[0][1]) == 5
    assert summary["masked"] == {"credentials": 1, "usernames": 1, "hostnames": 0, "reverse_dns_names": 0}
    _assert_checksums_good(out, tmp_path)


@needs_tshark
def test_snmp_community_is_masked(tmp_path):
    out, _ = _sanitize([_eth_ipv4_udp(CLIENT, SERVER, 40000, 161, snmp_get("s3cr3t-community"))])
    assert _tshark_fields(out, tmp_path, "snmp.community")[0][0] == "*" * len("s3cr3t-community")
    _assert_checksums_good(out, tmp_path)


@needs_tshark
def test_linux_cooked_v2_captures_are_sanitized(tmp_path):
    frame = sll2(CLIENT_MAC, 0x0800, ipv4(CLIENT, SERVER, 6, tcp(CLIENT, SERVER, 50000, 80, HTTP_WITH_AUTH)))
    out, _ = _sanitize([frame], linktype=276)
    row = _tshark_fields(out, tmp_path, "sll.src.eth", "ip.src", "http.authorization")[0]
    assert row[0] != "a4:bb:6d:01:02:03"
    assert row[1] != "192.168.1.10"
    assert "YWxp" not in row[2]
    _assert_checksums_good(out, tmp_path)


@needs_tshark
def test_strip_payload_keeps_headers_and_the_original_length(tmp_path):
    frames = [_eth_ipv4_tcp(CLIENT, SERVER, 50000, 80, HTTP_WITH_AUTH)]
    out, summary = _sanitize(frames, strip_payload=True)
    (incl, orig, frame), = read_pcap(out)
    assert incl == 14 + 20 + 20
    assert orig == len(frames[0])
    assert b"Authorization" not in frame
    assert summary["stripped_frames"] == 1
    assert _tshark_fields(out, tmp_path, "tcp.dstport")[0][0] == "80"


@needs_tshark
def test_payload_nothing_can_read_is_reported_by_port(tmp_path):
    frames = [_eth_ipv4_udp(CLIENT, SERVER, 40000, 31337, os.urandom(64)) for _ in range(3)]
    _, summary = _sanitize(frames)
    assert summary["undissected"] == [{"transport": "udp", "port": 31337, "frames": 3, "bytes": 3 * len(frames[0])}]


@needs_tshark
def test_only_the_options_ticked_are_applied(tmp_path):
    frames = [_eth_ipv4_tcp(CLIENT, SERVER, 50000, 80, HTTP_WITH_AUTH)]
    out, _ = _sanitize(frames, ips=False, macs=False)
    row = _tshark_fields(out, tmp_path, "eth.src", "ip.src", "http.authorization")[0]
    assert row[0] == "a4:bb:6d:01:02:03"
    assert row[1] == "192.168.1.10"
    assert "YWxp" not in row[2]


@needs_tshark
def test_a_saved_view_is_sanitized_through_its_filter(tmp_path):
    frames = [
        _eth_ipv4_tcp(CLIENT, SERVER, 50000, 80, HTTP_WITH_AUTH),
        _eth_ipv4_udp(RESOLVER, CLIENT, 53, 40000, dns_response_a("www.example.com", "93.184.216.34")),
    ]
    data = pcap(frames)
    summary = SanitizeSummary()

    async def run():
        source = FilteredSource(BytesSource(data, len(data)), "dns")
        out = bytearray()
        async for chunk in stream_sanitized_pcap(source, KEY, SanitizeOptions(), summary):
            out += chunk
        return bytes(out)

    out = asyncio.run(run())
    assert len(read_pcap(out)) == 1
    assert summary.frames == 1


@needs_tshark
def test_fields_nested_inside_another_protocol_are_found(tmp_path):
    """NTLMSSP rides inside HTTP, SMB2 and others rather than as a layer of its
    own. tshark's top-level layer filter (-J) cannot see it there, which is why
    the sanitizer does not use one. Inside HTTP it is base64, so it cannot be
    rewritten in place -- but it must be reported, and the header carrying it
    masked."""
    import base64
    import struct

    def field(data, offset):
        return struct.pack("<HHI", len(data), len(data), offset)

    user, domain = "alice".encode("utf-16-le"), "CORP".encode("utf-16-le")
    host, nt, lm = "LAPTOP7".encode("utf-16-le"), b"\x22" * 24, b"\x11" * 24
    body, headers, offset = b"", [], 64
    for data in (lm, nt, domain, user, host, b""):
        headers.append(field(data, offset + len(body)))
        body += data
    message = b"NTLMSSP\x00" + struct.pack("<I", 3) + b"".join(headers) + struct.pack("<I", 0x00088205) + body
    http = b"GET / HTTP/1.1\r\nHost: web\r\nAuthorization: NTLM " + base64.b64encode(message) + b"\r\n\r\n"

    out, summary = _sanitize([_eth_ipv4_tcp(CLIENT, SERVER, 50000, 80, http)], usernames=True)
    assert "ntlmssp.auth.username" in summary["unplaced"]
    assert base64.b64encode(message)[:40] not in out
    assert _tshark_fields(out, tmp_path, "http.authorization")[0][0].startswith("NTLM ****")


def test_tshark_json_is_split_into_packets_across_any_read_boundary(monkeypatch):
    from backend import sanitizer

    document = (
        b'[\n  {\n    "_source": {\n      "layers": {\n        "frame": {"frame.number": "1"}\n'
        b'      }\n    }\n  },\n  {\n    "_source": {\n      "layers": {\n'
        b'        "frame": {"frame.number": "2", "x": "  }"}\n      }\n    }\n  }\n]\n'
    )

    async def run(chunk):
        monkeypatch.setattr(sanitizer, "_JSON_READ_BYTES", chunk)
        reader = asyncio.StreamReader()
        reader.feed_data(document)
        reader.feed_eof()
        return [p async for p in sanitizer._json_packets(reader)]

    for chunk in (1, 2, 3, 5, 7, 64, 4096):
        packets = asyncio.run(run(chunk))
        assert [p["_source"]["layers"]["frame"]["frame.number"] for p in packets] == ["1", "2"]


def test_a_long_sanitize_lets_other_requests_run():
    """Rewriting is CPU work on the event loop. It has to give the loop back
    regularly, or one large download stalls every other user's requests."""
    frames = [_eth_ipv4_tcp(CLIENT, SERVER, 50000, 80, b"x" * 20)] * 640
    data = pcap(frames)

    async def run():
        ticks = 0
        done = False

        async def ticker():
            nonlocal ticks
            while not done:
                ticks += 1
                await asyncio.sleep(0)

        task = asyncio.create_task(ticker())
        async for _ in stream_sanitized_pcap(BytesSource(data, len(data), chunk_size=len(data)), KEY,
                                             SanitizeOptions(strip_payload=True), SanitizeSummary()):
            pass
        done = True
        await task
        return ticks

    assert asyncio.run(run()) >= 640 // 64


# --- what is refused ------------------------------------------------------------


def _check(data: bytes):
    return asyncio.run(check_capture(BytesSource(data, len(data))))


def test_an_unsupported_link_type_is_refused_before_anything_is_sent():
    with pytest.raises(SanitizeError, match="link type 127"):
        _check(pcap([b"\x00" * 40], linktype=127))


def test_pcapng_is_refused_by_name():
    with pytest.raises(SanitizeError, match="pcapng"):
        _check(b"\x0a\x0d\x0d\x0a" + b"\x00" * 40)


def test_a_truncated_record_fails_the_whole_download():
    data = pcap([_eth_ipv4_tcp(CLIENT, SERVER, 50000, 80, b"x" * 100)])[:-10]

    async def run():
        async for _ in stream_sanitized_pcap(BytesSource(data, len(data)), KEY,
                                             SanitizeOptions(strip_payload=True), SanitizeSummary()):
            pass

    with pytest.raises(SanitizeError, match="middle of a record"):
        asyncio.run(run())


# --- keys -----------------------------------------------------------------------


def test_an_encrypted_captures_key_survives_master_key_rotation(tmp_path):
    """The user's requirement: the same capture maps the same way every time,
    and rotating the master key is not allowed to change that."""
    old, new = Cryptor(os.urandom(32)), Cryptor(os.urandom(32))
    path = tmp_path / "c.pcap.enc"
    path.write_bytes(old.seal_bytes(pcap([b"\x00" * 60])))

    class Vault:
        def __init__(self, cryptor):
            from backend.vault import CaptureVault
            self._cryptor = cryptor
            self.derived_key = CaptureVault.derived_key.__get__(self)

    before = capture_key(Vault(old), path, "id", tmp_path)
    rekey_file(path, old, new, apply=True)
    after = capture_key(Vault(new), path, "id", tmp_path)
    assert before == after
    assert len(before) == 64


def test_two_encrypted_captures_do_not_share_a_key(tmp_path):
    cryptor = Cryptor(os.urandom(32))

    class Vault:
        def __init__(self):
            from backend.vault import CaptureVault
            self._cryptor = cryptor
            self.derived_key = CaptureVault.derived_key.__get__(self)

    keys = set()
    for name in ("a", "b"):
        path = tmp_path / f"{name}.pcap.enc"
        path.write_bytes(cryptor.seal_bytes(pcap([b"\x00" * 60])))
        keys.add(capture_key(Vault(), path, name, tmp_path))
    assert len(keys) == 2


def test_an_unencrypted_capture_uses_the_install_secret_and_its_id(tmp_path):
    path = tmp_path / "plain.pcap"
    path.write_bytes(pcap([b"\x00" * 60]))

    class Vault:
        def derived_key(self, *_):
            return None

    first = capture_key(Vault(), path, "capture-one", tmp_path)
    assert capture_key(Vault(), path, "capture-one", tmp_path) == first
    assert capture_key(Vault(), path, "capture-two", tmp_path) != first
    secret_file = tmp_path / INSTALL_SECRET_NAME
    assert stat.S_IMODE(secret_file.stat().st_mode) == 0o600
    assert not list(tmp_path.glob(f".{INSTALL_SECRET_NAME}.*"))


def test_a_damaged_install_secret_is_refused_rather_than_replaced(tmp_path):
    (tmp_path / INSTALL_SECRET_NAME).write_bytes(b"short")
    with pytest.raises(SanitizeError, match="damaged") as refused:
        install_secret(tmp_path)
    # The message reaches the browser; the data directory's path does not.
    assert str(tmp_path) not in str(refused.value)
    assert (tmp_path / INSTALL_SECRET_NAME).read_bytes() == b"short"


# --- routes ---------------------------------------------------------------------


@pytest.fixture()
def secure_client():
    with TestClient(main.app, base_url="https://testserver") as c:
        yield c


def _enrol(client) -> str:
    user_id = str(uuid.uuid4())
    main.db.create_user(user_id, f"sanitize-{user_id[:8]}", "scrypt$1$1$1$00$00", is_admin=False)
    main.db.set_totp_secret(user_id, "A" * 32)
    main.db.confirm_totp(user_id)
    token, _ = create_session_token(main.db, user_id)
    client.cookies.set("session", token)
    return user_id


@pytest.fixture()
def enrolled(secure_client):
    user_id = _enrol(secure_client)
    try:
        yield user_id
    finally:
        main.db.delete_user(user_id)


@pytest.fixture()
def sealed_capture(enrolled):
    """A finished capture, sealed with the running vault like a real one."""
    capture_id = str(uuid.uuid4())
    path = Path(os.environ["CAPTURES_DIR"]) / f"{capture_id}.pcap.enc"
    frames = [
        _eth_ipv4_tcp(CLIENT, SERVER, 50000, 80, HTTP_WITH_AUTH),
        _eth_ipv4_udp(RESOLVER, CLIENT, 53, 40000, dns_response_a("www.example.com", "93.184.216.34")),
    ]
    path.write_bytes(main.vault.cryptor.seal_bytes(pcap(frames)))
    info = CaptureInfo(
        id=capture_id, name="Lobby wifi", server_id="some-server", user_id=enrolled,
        status=CaptureStatus.COMPLETED, started_at=datetime.now(timezone.utc), local_path=str(path),
    )
    main.capture_manager._captures[capture_id] = info
    main.db.upsert_capture({
        **info.model_dump(), "status": info.status.value,
        "started_at": info.started_at.isoformat(), "stopped_at": None,
    })
    try:
        yield capture_id
    finally:
        main.capture_manager._captures.pop(capture_id, None)
        main.db.delete_capture(capture_id)
        path.unlink(missing_ok=True)


TICKET = "abcdefghijklmnop0123"


@needs_tshark
def test_a_sanitized_download_and_its_summary(secure_client, sealed_capture):
    resp = secure_client.get(f"/api/captures/{sealed_capture}/sanitize?hostnames=true&ticket={TICKET}")
    assert resp.status_code == 200
    assert resp.headers["content-disposition"] == 'attachment; filename="Lobby-wifi-sanitized.pcap"'
    assert b"YWxpY2U6aHVudGVyMg" not in resp.content
    assert len(read_pcap(resp.content)) == 2

    summary = secure_client.get(f"/api/captures/{sealed_capture}/sanitize/summary?ticket={TICKET}")
    assert summary.status_code == 200
    body = summary.json()
    assert body["done"] is True
    assert body["summary"]["frames"] == 2
    assert body["summary"]["masked"]["credentials"] == 3

    # Handed out once.
    again = secure_client.get(f"/api/captures/{sealed_capture}/sanitize/summary?ticket={TICKET}")
    assert again.status_code == 404


@needs_tshark
def test_two_downloads_of_one_capture_are_identical(secure_client, sealed_capture):
    first = secure_client.get(f"/api/captures/{sealed_capture}/sanitize").content
    second = secure_client.get(f"/api/captures/{sealed_capture}/sanitize").content
    assert first == second


@needs_tshark
def test_a_saved_views_sanitized_download_is_named_after_it(secure_client, sealed_capture):
    view = secure_client.post(
        f"/api/captures/{sealed_capture}/views",
        json={"name": "dns only", "display_filter": "dns"},
    ).json()
    resp = secure_client.get(f"/api/captures/{sealed_capture}/sanitize?view={view['id']}")
    assert resp.status_code == 200
    assert 'filename="Lobby-wifi-dns-only-sanitized.pcap"' in resp.headers["content-disposition"]
    assert len(read_pcap(resp.content)) == 1


def test_sanitizing_is_refused_over_plain_http(sealed_capture, enrolled):
    with TestClient(main.app) as http_client:
        token, _ = create_session_token(main.db, enrolled)
        http_client.cookies.set("session", token)
        resp = http_client.get(f"/api/captures/{sealed_capture}/sanitize")
        assert resp.status_code == 403
        assert resp.json()["detail"]["code"] == "https_required"


def test_nothing_ticked_is_refused(secure_client, sealed_capture):
    resp = secure_client.get(
        f"/api/captures/{sealed_capture}/sanitize?credentials=false&ips=false&macs=false"
    )
    assert resp.status_code == 400
    assert "at least one" in resp.json()["detail"]


def test_a_malformed_ticket_is_refused(secure_client, sealed_capture):
    assert secure_client.get(f"/api/captures/{sealed_capture}/sanitize?ticket=short").status_code == 400
    assert secure_client.get(
        f"/api/captures/{sealed_capture}/sanitize/summary?ticket=has%20a%20space%20in%20it!"
    ).status_code == 400


def test_an_unknown_view_is_404(secure_client, sealed_capture):
    assert secure_client.get(f"/api/captures/{sealed_capture}/sanitize?view=nope").status_code == 404


def test_someone_elses_capture_and_summary_are_404(sealed_capture):
    with TestClient(main.app, base_url="https://testserver") as other:
        other_id = _enrol(other)
        try:
            assert other.get(f"/api/captures/{sealed_capture}/sanitize").status_code == 404
            assert other.get(
                f"/api/captures/{sealed_capture}/sanitize/summary?ticket={TICKET}"
            ).status_code == 404
        finally:
            main.db.delete_user(other_id)


def test_the_filename_survives_a_name_that_could_break_the_header():
    info = CaptureInfo(
        id="cap-1", name='evil"\r\nX-Injected: 1', server_id="s",
        status=CaptureStatus.COMPLETED, started_at=datetime.now(timezone.utc),
    )
    name = main._sanitized_download_name(info, {"name": "a;b"})
    assert name == "evil-X-Injected-1-a-b-sanitized.pcap"
    blank = CaptureInfo(id="cap-2", server_id="s", status=CaptureStatus.COMPLETED,
                        started_at=datetime.now(timezone.utc))
    assert main._sanitized_download_name(blank, None) == "cap-2-sanitized.pcap"


def test_the_summary_store_is_bounded(monkeypatch):
    monkeypatch.setattr(main, "_sanitize_summaries", {})
    monkeypatch.setattr(main, "_SANITIZE_SUMMARY_LIMIT", 3)
    for i in range(5):
        main._remember_sanitize_summary(("u", "c", f"t{i}"), {"done": False})
    assert len(main._sanitize_summaries) == 3
    assert ("u", "c", "t4") in main._sanitize_summaries
