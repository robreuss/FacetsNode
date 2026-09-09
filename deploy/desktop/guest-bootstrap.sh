#!/bin/sh
set -eu
# Foundation artifact: only private appliance management, no workload services.
systemctl disable --now ssh.socket ssh.service 2>/dev/null || true
install -d -m 0700 /opt/fbd /srv/facets-box-data
chmod 0700 /opt/fbd/guest-agent
printf '%s\n' '[Unit]' 'Description=Facets Box private appliance management' 'After=local-fs.target' 'Before=docker.service containerd.service' '' '[Service]' 'Type=simple' 'ExecStartPre=-/opt/fbd/guest-agent prepare' 'ExecStart=/opt/fbd/guest-agent' 'Restart=no' 'UMask=0077' 'TimeoutStartSec=300' '' '[Install]' 'WantedBy=multi-user.target' > /etc/systemd/system/fbd-guest.service
systemctl daemon-reload
if ! systemctl enable --now fbd-guest.service; then
  # The private console is not exported. This contains only bounded agent failure
  # messages, never the cloud-init seed or installation credentials.
  systemctl --no-pager --full status fbd-guest.service > /dev/hvc0 2>&1 || true
  exit 1
fi
