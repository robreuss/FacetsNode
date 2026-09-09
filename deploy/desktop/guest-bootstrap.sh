#!/bin/sh
set -eu
systemctl disable --now ssh.socket ssh.service 2>/dev/null || true
install -d -m 0700 /opt/fbd /srv/facets-box-data
chmod 0700 /opt/fbd/guest-agent
# Keep a bounded journal across cold restarts of this working system so a guest
# lockup can be investigated after explicit force-stop. Console/journal output
# stays private and is not part of the redacted diagnostic export. The serial
# kernel setting takes effect on the next cold boot of this working system.
install -d -m 0755 /etc/systemd/journald.conf.d /etc/default/grub.d
cat > /etc/systemd/journald.conf.d/fbd-diagnostics.conf <<'JOURNAL'
[Journal]
Storage=persistent
SystemMaxUse=32M
RuntimeMaxUse=16M
MaxRetentionSec=7day
JOURNAL
install -d -m 2755 -g systemd-journal /var/log/journal
systemctl restart systemd-journald
journalctl --flush
cat > /etc/default/grub.d/99-fbd-console.cfg <<'GRUB'
GRUB_CMDLINE_LINUX_DEFAULT="${GRUB_CMDLINE_LINUX_DEFAULT} console=hvc0"
GRUB
update-grub >/opt/fbd/grub-configuration.log 2>&1
# Storage failure must not hide health reporting. Runtime services independently
# require the mount and check its identity, rather than relying on a directory.
cat > /etc/systemd/system/fbd-data.service <<'UNIT'
[Unit]
Description=Facets Box identified persistent storage
After=local-fs.target
Before=fbd-guest.service docker.service containerd.service docker.socket
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/opt/fbd/guest-agent prepare
ExecStop=/usr/bin/umount /srv/facets-box-data
TimeoutStartSec=300
TimeoutStopSec=120
UMask=0077
[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/fbd-guest.service <<'UNIT'
[Unit]
Description=Facets Box private appliance management
Wants=fbd-data.service
After=fbd-data.service docker.service containerd.service
[Service]
Type=simple
ExecStart=/opt/fbd/guest-agent
ExecStop=/opt/fbd/guest-agent stop-services
TimeoutStopSec=90
Restart=on-failure
RestartSec=3
UMask=0077
[Install]
WantedBy=multi-user.target
UNIT
for unit in docker.service containerd.service docker.socket; do
  install -d "/etc/systemd/system/$unit.d"
  cat > "/etc/systemd/system/$unit.d/fbd-storage.conf" <<'UNIT'
[Unit]
Requires=fbd-data.service
BindsTo=fbd-data.service
After=fbd-data.service
UNIT
done
for unit in docker.service containerd.service; do
  cat >> "/etc/systemd/system/$unit.d/fbd-storage.conf" <<'UNIT'
[Service]
ExecStartPre=/opt/fbd/guest-agent check-storage
UNIT
done
systemctl daemon-reload
systemctl enable fbd-data.service fbd-guest.service
systemctl start fbd-guest.service
