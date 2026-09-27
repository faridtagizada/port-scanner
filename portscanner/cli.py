"""Komanda sətri interfeysi."""
import argparse
import csv
import json
import sys
import time
from datetime import datetime

from . import __version__
from .scanner import parse_ports, resolve_target, scan


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="portscanner",
        description="Sadə TCP port scanner. Yalnız icazəniz olan sistemləri skan edin!")
    p.add_argument("target", help="IP ünvanı və ya hostname")
    p.add_argument("-p", "--ports", default="1-1024",
                   help="Portlar: '22,80', '1-1024' və ya 'common' (default: 1-1024)")
    p.add_argument("-t", "--threads", type=int, default=100, help="Thread sayı (default: 100)")
    p.add_argument("--timeout", type=float, default=1.0, help="Timeout saniyə ilə (default: 1.0)")
    p.add_argument("-b", "--banner", action="store_true", help="Banner grabbing")
    p.add_argument("-o", "--output", help="Nəticə faylı (.json və ya .csv)")
    p.add_argument("-v", "--version", action="version", version=__version__)
    return p


def print_table(results) -> None:
    print(f"{'PORT':<8}{'STATE':<8}{'SERVICE':<16}BANNER")
    print("-" * 60)
    for r in results:
        print(f"{r.port:<8}{r.state:<8}{r.service:<16}{r.banner or ''}")


def save(results, path: str, meta: dict) -> None:
    if path.endswith(".csv"):
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["port", "state", "service", "banner"])
            w.writeheader()
            w.writerows(r.to_dict() for r in results)
    else:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({**meta, "results": [r.to_dict() for r in results]},
                      f, indent=2, ensure_ascii=False)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        ports = parse_ports(args.ports)
        ip = resolve_target(args.target)
    except ValueError as exc:
        print(f"Xəta: {exc}", file=sys.stderr)
        return 1

    print(f"[*] Hədəf: {args.target} ({ip}) | {len(ports)} port | {datetime.now():%Y-%m-%d %H:%M:%S}")
    start = time.time()
    try:
        results = scan(ip, ports, args.threads, args.timeout, args.banner)
    except KeyboardInterrupt:
        print("\n[!] İstifadəçi tərəfindən dayandırıldı.")
        return 130
    elapsed = time.time() - start

    if results:
        print_table(results)
    else:
        print("Açıq port tapılmadı.")
    print(f"\n[+] {len(results)} açıq port, {elapsed:.2f} saniyə")

    if args.output:
        meta = {"target": args.target, "ip": ip, "scanned_ports": len(ports),
                "duration_sec": round(elapsed, 2),
                "timestamp": datetime.now().isoformat(timespec="seconds")}
        save(results, args.output, meta)
        print(f"[+] Nəticə yazıldı: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
