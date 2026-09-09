# Cisco ACL Helper

Windowsowa aplikacja (Python + Tkinter, budowana do pojedynczego `.exe`) do zarządzania
listami ACL na urządzeniach Cisco IOS / IOS-XE. Dwa języki: **polski / English**.

## Funkcje

- **Wyszukiwanie ACL** — wpisujesz IP, program łączy się przez SSH z listą urządzeń
  i pokazuje wpisy ACL zawierające to IP. Tryb negacji dodaje `no` + nagłówek
  `ip access-list extended`, a przycisk Kopiuj przenosi do schowka tylko treść
  gotową do wklejenia w CLI ( z jednego wybranego urządzenia, z końcowym Enterem).
- **Urządzenia** — lista routerów (IP, port, login, hasło, enable), przechowywana
  **szyfrowana** (Fernet, klucz z hasła głównego przez PBKDF2-SHA256).
  Przycisk **Duplikuj** kopiuje poświadczenia z wybranego urządzenia
  (do wypełnienia zostaje tylko nowe IP).
- **Podsieci** — mapowanie `podsieć (CIDR) → ACL-IN / ACL-OUT` (osobne listy
  dla kierunków in/out).
- **Generator ACL** — dla jednego komputera i wielu kamer generuje gotowy
  skrypt: `conf t` → `resequence … 10 10` → bloki `ip access-list extended`
  (IN: kamery → komputer, OUT: komputer → kamery) → `resequence` ponownie →
  `end` → `wr`. Sąsiadujące IP agreguje do CIDR (`host` vs `sieć wildcard`),
  numery sekwencji pobiera z urządzenia przez SSH (wolne, z pomijaniem zajętych,
  edytowalne przed kopiowaniem). Sprawdza też rezerwację DHCP komputera.
- **Ustawienia** — język, adres serwera DHCP, zmiana hasła głównego,
  opcjonalny log debugowania SSH (`ssh_debug.log`).

## SSH

Wyłącznie **SSHv2** (Paramiko). Aplikacja próbuje najpierw
`keyboard-interactive` (wymagane przez utwardzone konfiguracje AAA),
potem `password`; do tego wspiera legacy kex/hostkey
(`group1/group14-sha1`, `ssh-rsa`) oraz fallback z AES-GCM na AES-CTR.

## Wymagania (tylko do budowania)

- Windows + Python 3.10+
- `pip install -r requirements.txt` (`paramiko`, `cryptography`, `pyinstaller`)

Gotowy `.exe` nie wymaga Pythona ani instalacji.

## Budowanie

```powershell
powershell -ExecutionPolicy Bypass -File build_exe.ps1
# wynik: dist\CiscoACLHelper.exe
```

## Uruchomienie / pliki obok exe

| Plik           | Zawartość                                              |
|----------------|--------------------------------------------------------|
| `devices.enc`  | zaszyfrowane urządzenia + podsieci (hasło główne)      |
| `config.json`  | język, adres DHCP, flaga debug SSH (jawne)             |
| `ssh_debug.log`| log SSH, tylko gdy włączony w Ustawieniach             |

Pierwsze uruchomienie prosi o ustawienie **hasła głównego** — bez niego
nie da się odszyfrować `devices.enc`. Hasło trzymane jest tylko w pamięci.

## Diagnostyka bez GUI

```powershell
python ssh_test.py <host> <użytkownik> [port]    # pełny test logowania + ACL
python ssh_probe.py <host> [port]                # sam handshake (bez logowania)
```

## Kontrola DHCP

Sprawdzanie rezerwacji działa z uprawnieniami Twojego konta Windows:
najpierw cmdlety PowerShell DHCP (wymagają narzędzi RSAT DHCP + uprawnień
na serwerze), awaryjnie `netsh dhcp`. Brak możliwości weryfikacji to tylko
ostrzeżenie — generowanie działa dalej.

---

## English summary

Windows GUI app (Python + Tkinter, single `.exe`) helping manage ACLs on
Cisco IOS / IOS-XE devices over SSHv2: ACL search with negation mode,
encrypted per-device credentials, subnet→ACL-IN/OUT mapping, paste-ready
ACL generator (PC → many cameras, both directions, CIDR aggregation,
free sequence numbers fetched from the device, DHCP reservation check),
PL/EN interface. Build with `build_exe.ps1`; see table above for runtime files.
