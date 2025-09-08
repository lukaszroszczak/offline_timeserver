# Deploy offline_timeserver on Armbian (NanoPi/RPi)

This directory contains units and scripts we used to deploy on a NanoPi Neo (Armbian/Debian 12), with a u-blox 7 GPS on `/dev/ttyACM0` and chrony serving NTP to the LAN on `end0`.

## Prereqs
- `apt-get update && apt-get install -y git python3-venv python3-pip nftables gpsd gpsd-clients chrony`
- GPS appears as `/dev/ttyACM0` (see `ls -l /dev/serial/by-id/`)

## Install app
```
install -d /opt
git clone https://github.com/lukaszroszczak/offline_timeserver.git /opt/offline_timeserver
install -m 0644 /opt/offline_timeserver/deploy/armbian/systemd/offline_timeserver.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now offline_timeserver
```

## Configure gpsd
Edit `/etc/default/gpsd`:
```
START_DAEMON="true"
GPSD_OPTIONS="-n"
DEVICES="/dev/ttyACM0"
USBAUTO="false"
GPSD_SOCKET="/var/run/gpsd.sock"
```
Then: `systemctl enable --now gpsd`

## Configure chrony (GPS via SHM, serve LAN)
`/etc/chrony/chrony.conf` example:
```
driftfile /var/lib/chrony/chrony.drift
logdir /var/log/chrony
makestep 1.0 3

# GPS via gpsd shared memory (no PPS)
refclock SHM 0 refid GPS poll 4 precision 1e-1 offset 0.5 delay 0.2

# Allow from generated allow.conf
include /etc/chrony/allow.conf

# Provide time when isolated
local stratum 10
```

## Firewall + dynamic NTP allow based on `end0`
```
install -m 0755 /opt/offline_timeserver/deploy/armbian/scripts/update-ntp-allow /usr/local/sbin/
install -m 0644 /opt/offline_timeserver/deploy/armbian/systemd/update-ntp-allow.service /etc/systemd/system/
install -m 0644 /opt/offline_timeserver/deploy/armbian/systemd/update-ntp-allow.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now update-ntp-allow.service update-ntp-allow.timer
```
This sets nftables to:
- Allow SSH 22/tcp, HTTP 8000/tcp
- Allow NTP 123/udp only from `end0` subnets
- Drop other inbound

## Healthcheck
```
install -m 0755 /opt/offline_timeserver/deploy/armbian/scripts/timeserver-healthcheck /usr/local/bin/
install -m 0644 /opt/offline_timeserver/deploy/armbian/systemd/timeserver-healthcheck.service /etc/systemd/system/
install -m 0644 /opt/offline_timeserver/deploy/armbian/systemd/timeserver-healthcheck.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now timeserver-healthcheck.timer
```
The script checks:
- HTTP server on port 8000
- GPS TPV/fix via gpsd
- chrony sources and tracking

## Notes
- Adjust interface name if not `end0`.
- If Windows times out, verify client in same subnet, firewall allows UDP/123, and test with `w32tm /stripchart`.
