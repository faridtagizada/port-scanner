import socket
import threading

import pytest

from portscanner.scanner import parse_ports, scan, scan_port


def test_parse_single_and_list():
    assert parse_ports("22,80") == [22, 80]


def test_parse_range():
    assert parse_ports("20-23") == [20, 21, 22, 23]


def test_parse_mixed_dedup():
    assert parse_ports("22,20-23") == [20, 21, 22, 23]


def test_parse_common():
    ports = parse_ports("common")
    assert 22 in ports and 443 in ports


@pytest.mark.parametrize("bad", ["0", "70000", "30-20"])
def test_parse_invalid(bad):
    with pytest.raises(ValueError):
        parse_ports(bad)


@pytest.fixture
def server():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]

    def run():
        while True:
            try:
                conn, _ = srv.accept()
                conn.sendall(b"TEST-BANNER 1.0\r\n")
                conn.close()
            except OSError:
                break

    threading.Thread(target=run, daemon=True).start()
    yield port
    srv.close()


def test_open_port_with_banner(server):
    r = scan_port("127.0.0.1", server, timeout=1, banner=True)
    assert r.state == "open"
    assert r.banner == "TEST-BANNER 1.0"


def test_closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert scan_port("127.0.0.1", port, timeout=0.5).state == "closed"


def test_scan_returns_only_open(server):
    results = scan("127.0.0.1", [server, 1], threads=5, timeout=0.5)
    assert [r.port for r in results] == [server]
