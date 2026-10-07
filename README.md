# Cisco ACL Helper

Windowsowa aplikacja (Python + Tkinter, budowana do pojedynczego `.exe`) do zarządzania
listami ACL na urządzeniach Cisco IOS / IOS-XE. Dwa języki: **polski / English**.

## Funkcje

- **Wyszukiwanie ACL** — wpisujesz IP, program łączy się przez SSH z listą urządzeń
  i pokazuje wpisy ACL zawierające to IP. Tryb negacji dodaje `no` + nagłówek
  `ip access-list extended`, a przycisk Kopiuj przenosi do schowka tylko treść
  gotową do wklejenia w CLI ( z jednego wybranego urządzenia, z końcowym Enterem).
- **Urządzenia** — lista routerów (nazwa hosta, IP, port, login, hasło, enable),
  przechowywana **szyfrowana** (Fernet, klucz z hasła głównego przez PBKDF2-SHA256).
  Przycisk **Duplikuj** kopiuje poświadczenia z wybranego urządzenia
  (do wypełnienia zostaje tylko nowe IP i nazwa).
  Przycisk **Importuj** wczytuje urządzenia z pliku XML z auto-wykrywaniem
  formatu: **mRemoteNG** (`confCons.xml`, tylko połączenia SSH1/SSH2, hasła
  odszyfrowywane AES-GCM/AES-CBC kluczem domyślnym `mR3m` lub podanym
  hasłem głównym) albo **generyczny XML** (`<devices><device host="…"
  hostname="…" username="…" password="…" port="…" enable="…"/>` lub
  `<device><host>…</host>…</device>`, ewentualnie sama lista `<host>`).
  Jeden login/hasło/enable z dialogu pokrywa cały import (uzupełnia braki,
  opcjonalnie nadpisuje wszystko), a IP już będące na liście są pomijane
  (nigdy nie duplikowane).
- **Podsieci** — mapowanie `podsieć (CIDR) → ACL-IN / ACL-OUT` (osobne listy
  dla kierunków in/out).
- **Generator ACL** — dla jednego komputera i wielu kamer generuje gotowy
  skrypt: `conf t` → `resequence … 10 10` → bloki `ip access-list extended`
  (IN: kamery → komputer, OUT: komputer → kamery) → `resequence` ponownie →
   `end` → `wr`. Sąsiadujące IP agreguje do CIDR (`host` vs `sieć wildcard`),
   wpisy w każdej ACL sortuje rosnąco wg IP (IN po źródłowym, OUT po docelowym,
   tylko bezpieczne przestawienia jak w Audycie), numery sekwencji pobiera
   z urządzenia przez SSH (wolne, z pomijaniem zajętych,
   edytowalne przed kopiowaniem). Sprawdza też rezerwację DHCP komputera.
- **Audyt ACL** — pobiera jedną ACL z urządzenia i proponuje wersję
  zoptymalizowaną: bez duplikatów, z agregacją CIDR i bezpiecznym sortowaniem
  (wg IP źródłowego lub docelowego). Opcja grupowania wg DHCP otacza wpisy
  każdej osoby klamrą `remark` jak w generatorze, biorąc imię i nazwisko
  z opisu rezerwacji DHCP (znacznik BCS w dowolnym miejscu opisu).
- **Szukanie adresu** — namierzanie IP: `show ip arp` → MAC →
  `show mac address-table` → port → sąsiad `show cdp neighbors detail`.
  Przycisk kontynuacji prowadzi ślad przez kolejne switche (dopasowanie sąsiada
  po IP lub nazwie hosta, opcjonalnie logowanie poświadczeniami urządzenia
  nadrzędnego). Lista startowa pokazuje switche L3 (flaga w urządzeniu),
  domyślnie tylko primary z par HA (opcja Wszystkie pokazuje resztę).
  Gdy MAC wypada na porcie port-channel bez sąsiada CDP, ślad przechodzi
  automatycznie na sparowanego partnera HA (własne poświadczenia);
   brak wpisu na obu partnerach kończy się stosownym komunikatem.
   Urządzenie startowe w combo już nie podąża za hopami (zostaje wybrane
   przez operatora).    Wynik domyślnie kompaktowy (jedna linia na IP:
   gdzie znaleziono MAC i na którym porcie; gdy ślad stanie przed znanym
   sąsiadem, linia mówi „widziany na ... port ... — dalej w kierunku ...”); pełne logi hopów włącza
   checkbox Wyniki rozszerzone. Przycisk Masowo namierza listę adresów
   (po jednym na linię, błędne pomijane z adnotacją) po kolei z tego
   samego urządzenia startowego i z bieżącym ustawieniem auto-kontynuacji
   (domyślnie jeden hop na IP; dalsze hopsy tylko na Twoje żądanie
   przyciskiem Kontynuuj) — ślady lecą równolegle (do 5 naraz, wspólny
   Stop, odblokowanie raz na końcu; w trybie rozszerzonym bloki hopów
   mogą się przeplatać, ale każdy niesie swoje IP w nagłówku). Pad logowania na kolejnym hopie (np. inny
   username/password) zgłaszany wprost zamiast fałszywego „znaleziony”;
   przy auto-kontynuacji po padzie poświadczeniami rodzica następuje jedna
   próba zapisanymi danymi urządzenia z listy.
  Pary HA (primary/secondary) definiuje się w edycji urządzenia —
  druga strona linkowana jest automatycznie.
- **Podatności** — sprawdzanie podatności (nieszyfrowany Telnet:
  każda `line vty` musi mieć `transport input ssh`) na urządzeniach
  zaznaczonych ✓ w zakładce Urządzenia, równolegle do 5 hostów, wyniki
  kolorowane (czerwone/zielone). Opcja **Sprawdź wszystko** (domyślna)
  uruchamia wszystkie kontrole z listy naraz. Przycisk **Zastosuj poprawkę** pracuje
  bezpiecznie na jednej otwartej sesji: świeże sprawdzenie i pre-flight
  (świeże logowanie SSH) → konfiguracja → weryfikacja w running-config
  i automatyczny test nowej sesji SSH (przy odmowie natychmiastowy
  rollback bez pytania) → Twoje potwierdzenie (nowa sesja SSH do
  testu, przycisk **Otwórz w PuTTY** loguje danymi urządzenia —
  ścieżkę do `putty.exe` podajesz w Ustawieniach) → dopiero wtedy
  `write memory`, w razie odmowy rollback z weryfikacją.
- **Podatności c.d.: pakiet SSH** — druga pozycja na liście podatności:
  słabe MAC / KEX / szyfry CBC, Terrapin (CVE-2023-48795) i SSHv1.
  Sprawdzane handshake bez logowania (oferta serwera, jak skaner) plus
  `show ip ssh` / running-config / `show version`. Poprawka minimalna
  (oferowane minus flagowane) liniami `ip ssh server algorithm ...`
  tylko tam, gdzie switch je obsługuje (auto-wykrywanie z `show ip ssh`
  i wersji IOS-XE vs klasyczny IOS) — reszta trafia do opisu w OpenProject.
  Wdrażanie tym samym bezpiecznym protokołem co Telnet.
  Mapowanie 1:1 na tytuły skanera (identyczne w obu językach):
  | Tytuł skanera | Co program sprawdza w ofercie serwera |
  |---|---|
  | SSH Weak MAC Algorithms Enabled | MAC z MD5 / `*-96` / `umac-64*` |
  | SSH Weak Key Exchange Algorithms Enabled | `gex-sha1`, `group1-sha1`, `gss-*`, `rsa1024-sha1` |
  | SSH Server CBC Mode Ciphers Enabled | szyfry `*-cbc` |
  | SSH Terrapin Prefix Truncation Weakness (CVE-2023-48795) | ChaCha20 albo CBC+z-EtM bez strict-kex |
  | SSH Protocol Version 1 Session Key Retrieval | banner `SSH-1.x` / `version 1.99` |
- **Podatności c.d.: niezabezpieczony HTTP(S)** — trzecia pozycja: `TLS Version 1.0 Protocol Detection`. Polityka: serwer HTTP(S) ma być wyłączony na switchach (`no ip http server`, `no ip http secure-server`), więc check to obecność tych linii w running-config, a poprawka działa na każdym IOS. Kontrolery WLC są wykrywane z `show version` i pomijane z powodem do OpenProject.
- **Podatności c.d.: NTP mode 6** — czwarta pozycja: `Network Time Protocol (NTP) Mode 6 Scanner`. Check to nieuwierzytelniona sonda UDP mode 6 (jak skaner): odpowiedź = podatny, cisza = zgodny, ale dopiero po teście żywotności TCP na porcie SSH (padnięty host to błąd, nie OK). Poprawka to grupa `peer NTP-SERVERS` (jawnie wpuszcza skonfigurowane serwery `ntp server`/`peer`, żeby na takich trainach jak 2960S 15.2(1)E1 sam blok query-only nie odciął synchronizacji czasu) plus restrykcyjna grupa `query-only NTP-QUERY-BLOCK` (`deny any log`); synchronizacja czasu chroniona grupą peer, reszta ruchu bez zmian.
- **Historia poleceń** — przycisk na zakładce Podatności: każda paczka `configure` (fix, rollback) i każde `write memory` ląduje w historii sesji ze stemplem czasu, hostem i rodzajem; podgląd + kopiowanie do schowka pod komentarze audytowe. Fallback dla opornych skrzyń (np. 2960S na 15.2(1)E1, por. CSCum44673): gdy nasz blok query-only już jest, a sonda dalej słyszy odpowiedź, aplikacja proponuje wejściowy ACL `NTP-CTRL-IN` na interfejsie management (NTP tylko z serwerów z `ntp server`/`peer`) — wyłącznie gdy da się go w pełni przypiąć (host = literalny adres interfejsu z `show ip interface brief`, same adresy IPv4); w przeciwnym razie notatka do OpenProject zamiast daremnego dokładania tych samych linii.
- **Ustawienia** — język, adres serwera DHCP, zmiana hasła głównego,
  opcjonalny log debugowania SSH (`ssh_debug.log`).

## SSH

Wyłącznie **SSHv2** (Paramiko). Aplikacja próbuje najpierw
`keyboard-interactive` (wymagane przez utwardzone konfiguracje AAA),
potem `password`; do tego wspiera legacy kex/hostkey
(`group1/group14-sha1`, `ssh-rsa`, implementacje vendoryzowane w `ssh_legacy.py`)
oferowane ściśle jako last resort (nowoczesne algorytmy zawsze najpierw),
żeby dogadać się też ze switchami oferującymi wyłącznie group1
(typowo stare 2960); oraz fallback z AES-GCM na AES-CTR.

## Wymagania (tylko do budowania)

- Windows + Python 3.10+
- `pip install -r requirements.txt` (`paramiko`, `cryptography`, `pyinstaller`)

Gotowy `.exe` nie wymaga Pythona ani instalacji.

## Budowanie

```powershell
powershell -ExecutionPolicy Bypass -File build_exe.ps1
# wynik: dist\CiscoACLHelper\CiscoACLHelper.exe
#        + dist\CiscoACLHelper-windows.zip (do release)
```

Celowo `--onedir` (folder), nie pojedynczy plik: onefile rozpakowuje
~100 MB do tempa przy KAŻDYM starcie (wolno + skanowane przez antywirus),
folder startuje w ~1 s. Do dystrybucji służy zip z release.

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

## Testy

```powershell
python -m unittest discover -s tests -t .   # cała suita (stdlib, bez sieci)
```

Testy jednostkowe (`tests/`, tylko biblioteka standardowa) pokrywają analizę
Telnet, sortowanie, import XML (mRemoteNG AES-GCM/CBC + generyczny + merge),
`enable` na fejk-kanale oraz worker wdrażania poprawki na fejk-urządzeniu.
Testy okienkowe (`test_vuln_ui.py`) same się pomijają, gdy brak wyświetlacza.
Na każdy push GitHub Actions odpala suitę na Windows (`.github/workflows/tests.yml`).

## Struktura kodu

`app.py` trzyma szkielet aplikacji (okno, ustawienia, aktualizacje, magazyn
haseł, kolejka komunikatów). Logika zakładek żyje w mixinach
(`tab_search.py`, `tab_devices.py`, `tab_subnets.py`, `tab_gen.py`,
`tab_track.py`, `tab_audit.py`, `tab_vuln.py`), dialogi w `dialogs.py`.
Kontrakty podatności opisuje pamięć projektu (agent-memory #107).

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
