# Python Port Scanner

Python ilə yazılmış sadə, multi-thread **TCP connect port scanner**. Açıq portları tapır, servisləri müəyyən edir, banner oxuyur və nəticəni terminal, JSON və ya CSV formatında verir.

> ⚠️ **Xəbərdarlıq:** Yalnız özünüzə məxsus və ya skan etməyə yazılı icazəniz olan sistemləri skan edin. İcazəsiz skan qanunsuz ola bilər. Test üçün `127.0.0.1` və ya `scanme.nmap.org` istifadə edə bilərsiniz.

## Funksiyalar
- `socket` + `ThreadPoolExecutor` ilə sürətli paralel skan
- Port formatları: tək (`22`), siyahı (`22,80`), aralıq (`1-1024`), `common`
- Servis adının müəyyən edilməsi
- Banner grabbing (`-b`), HTTP portları üçün `HEAD` sorğusu
- Hostname → IP resolve
- Çıxış: terminal cədvəli, JSON, CSV
- `argparse` CLI və `pytest` testləri

## Quraşdırma
```bash
git clone https://github.com/<istifadəçi_adın>/port-scanner.git
cd port-scanner
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```
Python 3.8+ lazımdır. Skaner üçün əlavə kitabxana tələb olunmur (yalnız testlər üçün `pytest`).

## İstifadə
```bash
# Standart skan (1-1024)
python -m portscanner 127.0.0.1

# Ən çox rast gəlinən portlar + banner
python -m portscanner scanme.nmap.org -p common -b

# Konkret portlar, JSON çıxışı
python -m portscanner 192.168.1.1 -p 22,80,443 -o results/scan.json

# Bütün portlar, 200 thread, qısa timeout
python -m portscanner 127.0.0.1 -p 1-65535 -t 200 --timeout 0.5
```

| Parametr | Təsvir | Default |
|---|---|---|
| `-p, --ports` | Portlar | `1-1024` |
| `-t, --threads` | Thread sayı | `100` |
| `--timeout` | Timeout (san.) | `1.0` |
| `-b, --banner` | Banner grabbing | söndürülüb |
| `-o, --output` | `.json` və ya `.csv` fayl | – |

### Nümunə çıxış
```
[*] Hədəf: 127.0.0.1 (127.0.0.1) | 1024 port | 2026-10-08 14:30:00
PORT    STATE   SERVICE         BANNER
------------------------------------------------------------
22      open    ssh             SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13
80      open    http            HTTP/1.0 200 OK

[+] 2 açıq port, 1.04 saniyə
```
> Qeyd: Bu nümunədir; öz skanının real çıxışının ekran görüntüsü ilə əvəz et.

## Layihə strukturu
```
port-scanner/
├── portscanner/
│   ├── scanner.py    # skan məntiqi
│   ├── services.py   # port → servis adı
│   └── cli.py        # argparse CLI
├── tests/test_scanner.py
├── requirements.txt
└── README.md
```

## Testlər
```bash
pytest -v
```

## Necə işləyir
Hər port üçün TCP üçtərəfli əl sıxma (`connect_ex`) cəhd olunur. Bağlantı uğurlu olarsa port **open** sayılır. Thread pool minlərlə portu paralel yoxlayır.

## Gələcək planlar
- [ ] UDP skan
- [ ] CIDR aralığında (məs. `192.168.1.0/24`) host discovery
- [ ] SYN scan (`scapy` ilə)
- [ ] HTML hesabat

## Lisenziya
MIT
