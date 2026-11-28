#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

for command in qemu-system-x86_64 qemu-img xorriso ssh-keygen ssh-keyscan ssh ss sha512sum unshare ip socat setsid timeout jq dnsmasq dig; do
    command -v "$command" >/dev/null || { printf 'Missing required command: %s\n' "$command" >&2; exit 2; }
done
[[ "$(uname -m)" == x86_64 ]] || { printf 'This harness requires an x86_64 host.\n' >&2; exit 2; }
[[ "$(id -u)" != 0 ]] || { printf 'Run this harness as an unprivileged host user, not root.\n' >&2; exit 2; }
[[ -r /dev/kvm && -w /dev/kvm ]] || { printf 'KVM is unavailable to this user (/dev/kvm must be readable and writable).\n' >&2; exit 2; }

state_dir=$(mktemp -d /tmp/dorothy-traefik-acceptance.XXXXXXXX)
chmod 700 "$state_dir"
printf '%s\n' 'dorothy-traefik-acceptance-owned-state-v1' > "$state_dir/.owner"
chmod 600 "$state_dir/.owner"
instance_id=${state_dir##*.}
[[ "$instance_id" =~ ^[[:alnum:]]{8}$ ]] || { printf 'Generated an invalid private state identity.\n' >&2; exit 1; }
printf '%s\n' "$instance_id" > "$state_dir/.instance"
chmod 600 "$state_dir/.instance"

on_exit() {
    status=$?
    if (( status != 0 )); then
        bash "$script_dir/guest-barrier-check.sh" stop "$state_dir" >/dev/null 2>&1 || true
        printf 'Provisioning failed; private state retained at %s\n' "$state_dir" >&2
    fi
}
trap on_exit EXIT

mkdir -m 700 "$state_dir/seed" "$state_dir/bin" "$state_dir/pulumi-home" "$state_dir/backend"

image_name=debian-13-generic-amd64-20261123-2671.qcow2
expected_hash=562a4614952657a6ab8a89cda56eaf1bc85c8dfea51155184267bb6b6361eff215baf6afa2f8c2c8c2bad328ac6c30eead80664286ef4c8538368aeb7f87104f
bash "$script_dir/stage-fixture-assets.sh" "$state_dir"
[[ -s "$state_dir/$image_name" ]] || { printf 'Pinned Debian backing image was not staged.\n' >&2; exit 1; }
printf '%s  %s\n' "$expected_hash" "$state_dir/$image_name" | sha512sum --check --status
bash "$script_dir/stage-offline-deps.sh" "$state_dir"
qemu-img info "$state_dir/$image_name" >/dev/null
qemu-img create -q -f qcow2 -F qcow2 -b "$state_dir/$image_name" "$state_dir/guest.qcow2" 24G

ssh-keygen -q -t ed25519 -N '' -C 'dorothy-traefik-acceptance' -f "$state_dir/id_ed25519"
public_key=$(<"$state_dir/id_ed25519.pub")
mac_suffix=$(printf '%s' "$instance_id" | sha256sum | cut -c1-6)
qemu_mac="52:54:00:${mac_suffix:0:2}:${mac_suffix:2:2}:${mac_suffix:4:2}"
cat > "$state_dir/seed/user-data" <<EOF
#cloud-config
disable_root: false
ssh_pwauth: false
package_update: false
package_upgrade: false
package_reboot_if_required: false
ntp:
  enabled: false
users:
  - default
  - name: root
    lock_passwd: true
    shell: /bin/bash
    ssh_authorized_keys:
      - $public_key
write_files:
  - path: /etc/ssh/sshd_config.d/99-dorothy-acceptance-no-forwarding.conf
    permissions: '0644'
    content: |
      AllowTcpForwarding no
      AllowStreamLocalForwarding no
      AllowAgentForwarding no
      X11Forwarding no
      PermitTunnel no
      GatewayPorts no
      DisableForwarding yes
  - path: /etc/sysctl.d/90-dorothy-acceptance-network.conf
    permissions: '0644'
    content: |
      net.ipv6.conf.default.disable_ipv6 = 1
      net.ipv6.conf.isolated0.disable_ipv6 = 1
  - path: /usr/local/sbin/dorothy-acceptance-network-lockdown
    permissions: '0755'
    content: |
      #!/bin/sh
      set -eu
      printf 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6
      for interface_dir in /sys/class/net/*; do
        interface=\${interface_dir##*/}
        if [ "\$interface" != lo ]; then
          printf 1 > "/proc/sys/net/ipv6/conf/\$interface/disable_ipv6"
        fi
      done
      rm -f /etc/resolv.conf
      : > /etc/resolv.conf
      chmod 0644 /etc/resolv.conf
      systemctl mask --now systemd-timesyncd.service >/dev/null 2>&1 || true
      systemctl mask --now systemd-resolved.service >/dev/null 2>&1 || true
runcmd:
  - [bash, /usr/local/sbin/dorothy-acceptance-network-lockdown]
  - [systemctl, reload, ssh.service]
EOF
cat > "$state_dir/seed/network-config" <<EOF
version: 2
ethernets:
  isolated0:
    match:
      macaddress: "$qemu_mac"
    set-name: isolated0
    dhcp4: false
    dhcp6: false
    accept-ra: false
    addresses:
      - 10.0.2.15/24
    optional: true
EOF
cat > "$state_dir/seed/meta-data" <<EOF
instance-id: iid-dorothy-traefik-acceptance-$instance_id
local-hostname: dorothy-traefik-acceptance
dsmode: local
EOF
xorriso -as mkisofs -quiet -output "$state_dir/seed.iso" -volid cidata -joliet -rock \
    "$state_dir/seed/user-data" "$state_dir/seed/meta-data" "$state_dir/seed/network-config"

choose_port() {
    local first=$1 last=$2 candidate
    for _ in $(seq 1 200); do
        candidate=$((first + RANDOM % (last - first + 1)))
        if ! ss -H -ltn "sport = :$candidate" | grep -q .; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}
ssh_port=$(choose_port 40000 59999) || { printf 'Could not select an unused loopback SSH forwarding port.\n' >&2; exit 1; }
private_ssh_port=$(choose_port 20000 39999) || { printf 'Could not select a private SSH forwarding port.\n' >&2; exit 1; }
qemu_name="dorothy-traefik-acceptance-$instance_id"

cat > "$state_dir/ssh_config" <<EOF
Host *
    BatchMode yes
    ConnectTimeout 5
    StrictHostKeyChecking yes
    UserKnownHostsFile $state_dir/known_hosts
    IdentityFile $state_dir/id_ed25519
    IdentitiesOnly yes
    IdentityAgent none
    ControlMaster no
    ControlPath none
EOF
chmod 600 "$state_dir/ssh_config"
install -m 700 "$script_dir/ssh-wrapper.sh" "$state_dir/bin/ssh"

cat > "$state_dir/netns-bootstrap.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
state_dir=$1
private_ssh_port=$2
qemu_name=$3
qemu_path=$4
socat_path=$5
ip_path=$6
qemu_mac=$7
host_netns_inode=$8
host_userns_inode=$9

[[ "$(stat -Lc %i /proc/self/ns/net)" != "$host_netns_inode" ]] || {
    printf 'Network namespace creation failed.\n' >&2
    exit 1
}
[[ "$(stat -Lc %i /proc/self/ns/user)" != "$host_userns_inode" ]] || {
    printf 'Unprivileged user namespace creation failed.\n' >&2
    exit 1
}
"$ip_path" link set lo up
links=$("$ip_path" -o link show | awk -F': ' '{ name=$2; sub(/@.*/, "", name); sub(/[[:space:]].*/, "", name); print name }')
[[ "$links" == lo ]] || { printf 'The QEMU namespace has a non-loopback interface.\n' >&2; exit 1; }
nonlocal_routes() {
    "$ip_path" "-$1" route show table all | awk -v family="$1" '
        {
            kind=$1
            if (kind != "local" && kind != "broadcast" && kind != "multicast") { print; next }
            destination=$2
            device=""
            via=0
            for (i=1; i<=NF; i++) {
                if ($i == "dev") device=$(i+1)
                if ($i == "via") via=1
            }
            if (device != "lo" || via) { print; next }
            if (family == 4 && destination !~ /^127([.]|$)/) print
            if (family == 6 && destination !~ /^::1([/]|$)/ && destination !~ /^ff([0-9a-fA-F]{0,2})?:/) print
        }'
}
routes4=$(nonlocal_routes 4)
routes6=$(nonlocal_routes 6)
[[ -z "$routes4" && -z "$routes6" ]] || {
    printf 'Refusing to launch QEMU with a non-loopback IPv4/IPv6 route.\n' >&2
    exit 1
}

printf '%s\n' "$(stat -Lc %i /proc/self/ns/net)" > "$state_dir/netns.inode"
chmod 600 "$state_dir/netns.inode"
setsid --fork /bin/sh -c 'umask 077; printf "%s\n" "$$" > "$1"; shift; exec "$@"' \
    sh "$state_dir/private-relay.pid" "$socat_path" \
    "UNIX-LISTEN:$state_dir/ssh-relay.sock,unlink-early,mode=600,fork" \
    "TCP4:127.0.0.1:$private_ssh_port" \
    </dev/null > "$state_dir/private-relay.log" 2>&1
for _ in $(seq 1 100); do
    [[ -S "$state_dir/ssh-relay.sock" ]] && break
    if [[ -s "$state_dir/private-relay.pid" ]] && ! kill -0 "$(<"$state_dir/private-relay.pid")" 2>/dev/null; then echo 'Private relay exited.' >&2; exit 1; fi
    sleep 0.05
done
[[ -S "$state_dir/ssh-relay.sock" ]] || { printf 'Private relay did not create its socket.\n' >&2; exit 1; }

"$qemu_path" \
    -name "$qemu_name" \
    -enable-kvm \
    -machine q35 \
    -cpu host \
    -m 4096 \
    -smp 2 \
    -drive "file=$state_dir/guest.qcow2,if=virtio,format=qcow2" \
    -drive "file=$state_dir/seed.iso,media=cdrom,readonly=on" \
    -netdev "user,id=net0,restrict=on,ipv6=off,hostfwd=tcp:127.0.0.1:$private_ssh_port-10.0.2.15:22" \
    -device "virtio-net-pci,netdev=net0,mac=$qemu_mac" \
    -display none \
    -serial "file:$state_dir/serial.log" \
    -monitor "unix:$state_dir/qemu-monitor.sock,server=on,wait=off" \
    -daemonize \
    -pidfile "$state_dir/qemu.pid" \
    </dev/null >> "$state_dir/qemu-launch.log" 2>&1
EOF
chmod 700 "$state_dir/netns-bootstrap.sh"

host_netns_before=$(stat -Lc %i /proc/self/ns/net)
host_userns_before=$(stat -Lc %i /proc/self/ns/user)
unshare --user --map-root-user --net --fork \
    /usr/bin/env -i HOME="$state_dir" PATH=/usr/bin:/bin LC_ALL=C \
    /bin/bash "$state_dir/netns-bootstrap.sh" \
    "$state_dir" "$private_ssh_port" "$qemu_name" \
    "$(readlink -f -- "$(command -v qemu-system-x86_64)")" \
    "$(readlink -f -- "$(command -v socat)")" \
    "$(readlink -f -- "$(command -v ip)")" "$qemu_mac" "$host_netns_before" "$host_userns_before" \
    </dev/null > "$state_dir/netns-bootstrap.log" 2>&1
setsid --fork /bin/sh -c 'umask 077; printf "%s\n" "$$" > "$1"; shift; exec "$@"' \
    sh "$state_dir/host-relay.pid" /usr/bin/socat \
    "TCP4-LISTEN:$ssh_port,bind=127.0.0.1,reuseaddr,fork" \
    "UNIX-CONNECT:$state_dir/ssh-relay.sock" \
    </dev/null > "$state_dir/host-relay.log" 2>&1
for _ in $(seq 1 100); do [[ -s "$state_dir/host-relay.pid" ]] && break; sleep 0.05; done
host_relay_pid=$(<"$state_dir/host-relay.pid")
[[ "$host_relay_pid" =~ ^[0-9]+$ && -r "/proc/$host_relay_pid/stat" ]] || { echo 'Host relay exited.' >&2; exit 1; }

qemu_pid=$(<"$state_dir/qemu.pid")
[[ "$qemu_pid" =~ ^[0-9]+$ ]] || { printf 'QEMU wrote an invalid pid file.\n' >&2; exit 1; }
qemu_start_ticks=$(awk '{ print $22 }' "/proc/$qemu_pid/stat")
private_relay_pid=$(<"$state_dir/private-relay.pid")
private_relay_start_ticks=$(awk '{ print $22 }' "/proc/$private_relay_pid/stat")
host_relay_start_ticks=$(awk '{ print $22 }' "/proc/$host_relay_pid/stat")
netns_inode=$(stat -Lc %i "/proc/$qemu_pid/ns/net")
userns_inode=$(stat -Lc %i "/proc/$qemu_pid/ns/user")
host_netns_inode=$(stat -Lc %i /proc/self/ns/net)
host_userns_inode=$(stat -Lc %i /proc/self/ns/user)
uid_map=$(awk 'NF { printf "%s%s %s %s", (NR == 1 ? "" : ";"), $1, $2, $3 }' "/proc/$qemu_pid/uid_map")
backing_image_sha512=$(sha512sum "$state_dir/$image_name" | awk '{ print $1 }')
printf 'instance_id=%s\nhost_uid=%s\nhost_netns_inode=%s\nhost_userns_inode=%s\nqemu_pid=%s\nqemu_start_ticks=%s\nnetns_inode=%s\nuserns_inode=%s\nuid_map=%s\nqemu_mac=%s\nprivate_ssh_port=%s\nssh_port=%s\nbacking_image_sha512=%s\n' \
    "$instance_id" "$(id -u)" "$host_netns_inode" "$host_userns_inode" "$qemu_pid" "$qemu_start_ticks" \
    "$netns_inode" "$userns_inode" "$uid_map" "$qemu_mac" "$private_ssh_port" "$ssh_port" "$backing_image_sha512" \
    > "$state_dir/network.identity"
printf '%s\n' "$private_relay_pid" > "$state_dir/private-relay.pid"
printf '%s\n' "$private_relay_start_ticks" > "$state_dir/private-relay.start"
printf '%s\n' "$host_relay_start_ticks" > "$state_dir/host-relay.start"
chmod 600 "$state_dir/network.identity" "$state_dir/private-relay.start" "$state_dir/host-relay.start"

printf 'STATE_DIR=%q\n' "$state_dir" > "$state_dir/handle.env"
printf 'SSH_HOST=%q\nSSH_PORT=%q\nSSH_USER=%q\nSSH_IDENTITY=%q\nSSH_CONFIG=%q\nQEMU_PID_FILE=%q\n' \
    127.0.0.1 "$ssh_port" root "$state_dir/id_ed25519" "$state_dir/ssh_config" "$state_dir/qemu.pid" >> "$state_dir/handle.env"
printf 'INSTANCE_ID=%q\nQEMU_PID=%q\nQEMU_NAME=%q\nQEMU_MAC=%q\nQEMU_NETNS_INODE=%q\nPRIVATE_SSH_PORT=%q\nRELAY_SOCKET=%q\nHOST_RELAY_PID_FILE=%q\nPRIVATE_RELAY_PID_FILE=%q\nBACKING_IMAGE_SHA512=%q\n' \
    "$instance_id" "$qemu_pid" "$qemu_name" "$qemu_mac" "$netns_inode" "$private_ssh_port" "$state_dir/ssh-relay.sock" \
    "$state_dir/host-relay.pid" "$state_dir/private-relay.pid" "$backing_image_sha512" >> "$state_dir/handle.env"
chmod 600 "$state_dir/handle.env"

bash "$script_dir/guest-barrier-check.sh" precondition "$state_dir"
for _ in $(seq 1 240); do
    if [[ ! -s "$state_dir/known_hosts" ]]; then
        if ssh-keyscan -T 2 -p "$ssh_port" 127.0.0.1 > "$state_dir/known_hosts.tmp" 2>/dev/null && [[ -s "$state_dir/known_hosts.tmp" ]]; then
            chmod 600 "$state_dir/known_hosts.tmp"
            mv "$state_dir/known_hosts.tmp" "$state_dir/known_hosts"
        fi
    fi
    if [[ -s "$state_dir/known_hosts" ]] && /usr/bin/ssh -F "$state_dir/ssh_config" -p "$ssh_port" root@127.0.0.1 true 2>/dev/null; then
        break
    fi
    sleep 2
done
[[ -s "$state_dir/known_hosts" ]] || { printf 'Guest SSH did not become reachable; inspect %s/serial.log\n' "$state_dir" >&2; exit 1; }
/usr/bin/ssh -F "$state_dir/ssh_config" -p "$ssh_port" root@127.0.0.1 'cloud-init status --wait'
timeout 600 bash "$script_dir/install-offline-deps.sh" "$state_dir"
bash "$script_dir/guest-barrier-check.sh" precondition "$state_dir"

printf '\nDisposable Debian guest is ready in an isolated, egress-blocked namespace.\n'
printf 'State directory: %s\n' "$state_dir"
printf 'SSH handle: root@127.0.0.1:%s\n' "$ssh_port"
printf 'Identity: %s\n' "$state_dir/id_ed25519"
printf 'Known-hosts: %s/known_hosts\n' "$state_dir"
printf 'QEMU pid: %s\n' "$qemu_pid"
printf 'Saved handle: %s/handle.env\n' "$state_dir"
printf 'After prepare-services, run: tests/Traefik.Acceptance/guest-barrier-check.sh receipt %q\n' "$state_dir"
printf 'Cleanup: tests/Traefik.Acceptance/cleanup.sh %q\n' "$state_dir"
