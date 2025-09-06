# timeserver

Zestaw narzędzi do lokalnego serwowania czasu w odłączonej sieci:

- Prosty serwer HTTP (demo) zwracający czas jako JSON.
- Konfiguracja SBC (np. Raspberry Pi) jako serwera NTP z GPS (+PPS) dla LAN.

Ważne: serwer czasu w sieci używa standardowo protokołu NTP na porcie UDP/123 (nie 53 — to port DNS). Jeśli chcesz, możemy dodać DNS/DHCP (dnsmasq) na 53, aby rozgłaszać adres serwera NTP klientom (DHCP option 42).

## 1) Python HTTP demo

- Wymagania: Python 3.8+
- Start: `python3 server.py` (domyślnie 0.0.0.0:8000)
- Endpointy:
  - `GET /` — info
  - `GET /time` — aktualny czas UTC w JSON

## 2) Raspberry Pi jako serwer NTP z GPS

W katalogu `raspi-ntp/` znajdziesz skrypty i szablony konfiguracji dla chrony + gpsd.

Skrót założeń:

- Źródło czasu: moduł GPS (NMEA, opcjonalnie PPS) przez `/dev/ttyACM0` lub `/dev/ttyUSB0`.
- Usługa NTP: `chrony` (nasłuch na UDP/123, serwuje czas dla LAN).
- Offline: brak serwerów z Internetu, `local stratum` ustawione dla stabilnego działania bez GPS.
- (Opcjonalnie) DNS/DHCP: `dnsmasq` na porcie 53, rozgłasza NTP (DHCP Option 42).

Szybki start na Raspberry Pi (Bookworm/Bullseye):

1. Podłącz GPS (USB lub UART). Jeśli masz PPS, podłącz go np. do GPIO18.
2. `sudo apt update && sudo apt install -y chrony gpsd gpsd-clients pps-tools`
3. Skopiuj i dostosuj pliki z `raspi-ntp/` (opis w `raspi-ntp/README.md`).
4. Uruchom `sudo raspi-ntp/setup.sh` (zatrzyma usługi, podmieni konfigurację, włączy NTP dla LAN).
5. Weryfikacja: `chronyc sources -v`, `chronyc tracking`, `gpsmon`/`gpspipe -r`.

Klienci w sieci powinni wskazywać adres SBC jako serwer NTP (np. 192.168.x.x). Jeśli używasz DHCP, rozgłaszaj go przez Option 42 (przykład w `raspi-ntp/dnsmasq.conf.example`).
