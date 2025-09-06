#!/usr/bin/env bash
# Healthcheck dla offline_timeserver na Raspberry Pi
# Sprawdza gpsd, chrony (SHM, PPS), urządzenia i nasłuch NTP.

set -uo pipefail

ok=()
warn=()
fail=()

log() { printf "%s\n" "$*"; }
add_ok() { ok+=("$*"); }
add_warn() { warn+=("$*"); }
add_fail() { fail+=("$*"); }

has_cmd() { command -v "$1" >/dev/null 2>&1; }

get_gps_device() {
  local dev conf=/etc/default/gpsd
  if [ -r "$conf" ]; then
    dev=$(awk -F '="|"' '/^DEVICES=/{print $2}' "$conf" | awk '{print $1}')
    if [ -n "${dev:-}" ] && [ -e "$dev" ]; then
      echo "$dev"; return 0
    fi
  fi
  for c in /dev/ttyACM* /dev/ttyUSB*; do
    [ -e "$c" ] || continue
    echo "$c"; return 0
  done
  echo ""; return 1
}

ppstest_run() {
  local dev=/dev/pps0
  if [ ! -e "$dev" ]; then
    add_warn "Brak $dev (PPS nieaktywny)"; return 0
  fi
  if ! has_cmd ppstest; then
    add_warn "Brak narzędzia ppstest (pps-tools) — pomijam test PPS"; return 0
  fi
  # Spróbuj złapać kilka impulsów PPS (może wymagać sudo)
  if timeout 3s ppstest "$dev" >/dev/null 2>&1 || timeout 3s sudo ppstest "$dev" >/dev/null 2>&1; then
    add_ok "PPS: /dev/pps0 odpowiada (ppstest)"
  else
    add_warn "PPS: /dev/pps0 nie odpowiada (ppstest nieudany)"
  fi
}

section() { printf "\n== %s ==\n" "$*"; }

main() {
  section "Wersje narzędzi"
  has_cmd chronyc && chronyc --version 2>/dev/null | head -n1 || log "chronyc: brak"
  has_cmd gpsd && gpsd -V 2>/dev/null | head -n1 || log "gpsd: brak"
  has_cmd gpspipe && gpspipe -h >/dev/null 2>&1 && log "gpspipe: OK" || log "gpspipe: brak"

  section "Usługi systemowe"
  if has_cmd systemctl; then
    systemctl is-active --quiet gpsd && add_ok "gpsd: active" || add_fail "gpsd: inactive"
    systemctl is-active --quiet chrony && add_ok "chrony: active" || add_fail "chrony: inactive"
  else
    add_warn "Brak systemctl — pomijam sprawdzanie usług"
  fi

  section "Urządzenia GPS/PPS"
  local gps_dev
  gps_dev=$(get_gps_device) || true
  if [ -n "$gps_dev" ]; then
    add_ok "GPS device: $gps_dev"
  else
    add_fail "Nie znaleziono urządzenia GPS (/dev/ttyACM* ani /dev/ttyUSB*)"
  fi
  if [ -e /dev/pps0 ]; then
    add_ok "PPS device: /dev/pps0"
  else
    add_warn "Brak /dev/pps0 (PPS nieaktywne lub brak overlay)"
  fi

  section "Dane z GPS (NMEA)"
  if has_cmd gpspipe; then
    if gpspipe -r -n 5 2>/dev/null | sed -n '1,5p' | tee /tmp/gps_nmea.out | grep -q '^\$GP'; then
      add_ok "NMEA: strumień dostępny (gpspipe)"
    else
      add_warn "NMEA: brak zdań z gpspipe - sprawdź gpsd i DEVICES"
    fi
  else
    add_warn "gpspipe nie jest dostępny — pomijam test NMEA"
  fi

  section "chrony: źródła i tracking"
  if has_cmd chronyc; then
    chronyc sources -v 2>/dev/null | sed -n '1,120p'
    chronyc tracking 2>/dev/null | sed -n '1,120p'
    if chronyc sources 2>/dev/null | grep -Eiq 'SHM|GPS'; then
      add_ok "chrony: widzi źródło GPS/SHM"
    else
      add_fail "chrony: nie widzi GPS/SHM — sprawdź refclock SHM i gpsd"
    fi
    if chronyc sources 2>/dev/null | grep -q 'PPS'; then
      add_ok "chrony: widzi PPS"
    else
      add_warn "chrony: brak PPS w źródłach (opcjonalne)"
    fi
  else
    add_fail "Brak chronyc — czy chrony jest zainstalowane?"
  fi

  section "Nasłuch NTP (UDP/123)"
  if has_cmd ss; then
    if ss -ulpn | grep -q ':123'; then
      add_ok "Port UDP/123 nasłuchuje"
    else
      add_fail "Port UDP/123 nie nasłuchuje — sprawdź chrony i firewall"
    fi
  else
    add_warn "Brak 'ss' — pomijam sprawdzanie portu 123"
  fi

  section "PPS test (opcjonalny)"
  ppstest_run

  section "Podsumowanie"
  for m in "${ok[@]:-}"; do [ -n "$m" ] && echo "OK:    $m"; done
  for m in "${warn[@]:-}"; do [ -n "$m" ] && echo "WARN:  $m"; done
  for m in "${fail[@]:-}"; do [ -n "$m" ] && echo "FAIL:  $m"; done

  [ ${#fail[@]:-0} -eq 0 ] || exit 1
}

main "$@"

