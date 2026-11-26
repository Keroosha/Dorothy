#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

for command in curl qemu-system-x86_64 qemu-img xorriso ssh-keygen ssh-keyscan ssh ss sha512sum; do
    command -v "$command" >/dev/null || { printf 'Missing required command: %s\n' "$command" >&2; exit 2; }
done
[[ "$(uname -m)" == x86_64 ]] || { printf 'This harness requires an x86_64 host.\n' >&2; exit 2; }
[[ -r /dev/kvm && -w /dev/kvm ]] || { printf 'KVM is unavailable to this user (/dev/kvm must be readable and writable).\n' >&2; exit 2; }

state_dir=$(mktemp -d /tmp/dorothy-traefik-acceptance.XXXXXXXX)
chmod 700 "$state_dir"
printf '%s\n' 'dorothy-traefik-acceptance-owned-state-v1' > "$state_dir/.owner"
chmod 600 "$state_dir/.owner"

on_exit() {
    status=$?
    if (( status != 0 )); then
        if [[ -s "$state_dir/qemu.pid" ]]; then
            pid=$(<"$state_dir/qemu.pid")
            kill "$pid" 2>/dev/null || true
        fi
        printf 'Provisioning failed; private state retained at %s\n' "$state_dir" >&2
    fi
}
trap on_exit EXIT

mkdir -m 700 "$state_dir/seed" "$state_dir/bin" "$state_dir/pulumi-home" "$state_dir/backend"
ssh-keygen -q -t ed25519 -N '' -C 'dorothy-traefik-acceptance' -f "$state_dir/id_ed25519"

image_name=debian-13-generic-amd64-20261123-2671.qcow2
image_url=https://cloud.debian.org/images/cloud/trixie/20261123-2671
expected_hash=562a4614952657a6ab8a89cda56eaf1bc85c8dfea51155184267bb6b6361eff215baf6afa2f8c2c8c2bad328ac6c30eead80664286ef4c8538368aeb7f87104f
curl --fail --location --silent --show-error --retry 3 "$image_url/$image_name" -o "$state_dir/$image_name"
printf '%s  %s\n' "$expected_hash" "$state_dir/$image_name" | sha512sum --check --status
qemu-img info "$state_dir/$image_name" >/dev/null
qemu-img create -q -f qcow2 -F qcow2 -b "$state_dir/$image_name" "$state_dir/guest.qcow2" 24G

public_key=$(<"$state_dir/id_ed25519.pub")
cat > "$state_dir/seed/user-data" <<EOF
#cloud-config
disable_root: false
ssh_pwauth: false
users:
  - default
  - name: root
    lock_passwd: true
    shell: /bin/bash
    ssh_authorized_keys:
      - $public_key
EOF
cat > "$state_dir/seed/meta-data" <<EOF
instance-id: iid-dorothy-traefik-acceptance-$(basename "$state_dir")
local-hostname: dorothy-traefik-acceptance
EOF
xorriso -as mkisofs -quiet -output "$state_dir/seed.iso" -volid cidata -joliet -rock "$state_dir/seed/user-data" "$state_dir/seed/meta-data"

ssh_port=''
for _ in $(seq 1 100); do
    candidate=$((40000 + RANDOM % 20000))
    if ! ss -H -ltn "sport = :$candidate" | grep -q .; then
        ssh_port=$candidate
        break
    fi
done
[[ -n "$ssh_port" ]] || { printf 'Could not select an unused loopback SSH forwarding port.\n' >&2; exit 1; }

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

qemu-system-x86_64 \
    -enable-kvm \
    -machine q35 \
    -cpu host \
    -m 4096 \
    -smp 2 \
    -drive "file=$state_dir/guest.qcow2,if=virtio,format=qcow2" \
    -drive "file=$state_dir/seed.iso,media=cdrom,readonly=on" \
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$ssh_port-:22" \
    -device virtio-net-pci,netdev=net0 \
    -display none \
    -serial "file:$state_dir/serial.log" \
    -monitor "unix:$state_dir/qemu-monitor.sock,server=on,wait=off" \
    -daemonize \
    -pidfile "$state_dir/qemu.pid"

printf 'STATE_DIR=%q\n' "$state_dir" > "$state_dir/handle.env"
printf 'SSH_HOST=%q\nSSH_PORT=%q\nSSH_USER=%q\nSSH_IDENTITY=%q\nSSH_CONFIG=%q\nQEMU_PID_FILE=%q\n' \
    127.0.0.1 "$ssh_port" root "$state_dir/id_ed25519" "$state_dir/ssh_config" "$state_dir/qemu.pid" >> "$state_dir/handle.env"
chmod 600 "$state_dir/handle.env"

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
timeout 600 /usr/bin/ssh -F "$state_dir/ssh_config" -p "$ssh_port" root@127.0.0.1 \
    'export DEBIAN_FRONTEND=noninteractive; apt-get update; apt-get install --no-install-recommends -y bind9 bind9-utils ca-certificates curl dnsutils jq nginx openssl socat netcat-openbsd iproute2 tcpdump'

printf '\nDisposable Debian guest is ready.\n'
printf 'State directory: %s\n' "$state_dir"
printf 'SSH handle: root@127.0.0.1:%s\n' "$ssh_port"
printf 'Identity: %s\n' "$state_dir/id_ed25519"
printf 'Known-hosts: %s/known_hosts\n' "$state_dir"
printf 'QEMU pid: %s\n' "$(<"$state_dir/qemu.pid")"
printf 'Saved handle: %s/handle.env\n' "$state_dir"
printf 'Cleanup: tests/Traefik.Acceptance/cleanup.sh %q\n' "$state_dir"
