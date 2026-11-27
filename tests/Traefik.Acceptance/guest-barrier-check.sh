#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
usage() {
    printf 'Usage: %s {precondition|receipt|acceptance|stop} STATE_DIR\n' "$0" >&2
    printf '       %s authorize STATE_DIR RECEIPT_SHA256  # after independent review\n' "$0" >&2
    exit 2
}
if [[ ${1-} == authorize ]]; then
    [[ $# == 3 ]] || usage
    mode=authorize
    state_arg=$2
    reviewed_receipt_sha256=$3
    [[ "$reviewed_receipt_sha256" =~ ^[0-9a-f]{64}$ ]] || { printf 'Authorization requires the exact lowercase SHA-256 of the reviewed receipt.\n' >&2; exit 2; }
else
    [[ $# == 2 ]] || usage
    mode=$1
    state_arg=$2
fi
case "$mode" in precondition|receipt|acceptance|authorize|stop) ;; *) usage ;; esac
[[ -d "$state_arg" && ! -L "$state_arg" ]] || { printf 'Refusing an absent or symlinked state directory.\n' >&2; exit 2; }
state_dir=$(realpath -e -- "$state_arg")
case "$state_dir" in /tmp/dorothy-traefik-acceptance.*) ;; *) printf 'Refusing a state directory outside the private acceptance temp root.\n' >&2; exit 2 ;; esac
[[ -f "$state_dir/.owner" && ! -L "$state_dir/.owner" ]] || { printf 'Refusing an unmarked acceptance directory.\n' >&2; exit 2; }
[[ "$(<"$state_dir/.owner")" == dorothy-traefik-acceptance-owned-state-v1 ]] || { printf 'Ownership marker does not match.\n' >&2; exit 2; }
[[ "$(stat -c %a "$state_dir")" == 700 && "$(stat -c %u "$state_dir")" == "$(id -u)" ]] || { printf 'The private state directory has unexpected ownership or permissions.\n' >&2; exit 2; }

proc_start_ticks() {
    local line rest
    line=$(<"/proc/$1/stat") || return 1
    rest=${line##*) }
    local -a fields
    read -r -a fields <<< "$rest"
    [[ ${#fields[@]} -ge 20 ]] || return 1
    printf '%s\n' "${fields[19]}"
}
proc_pgrp() {
    local line rest
    line=$(<"/proc/$1/stat") || return 1
    rest=${line##*) }
    local -a fields
    read -r -a fields <<< "$rest"
    [[ ${#fields[@]} -ge 3 ]] || return 1
    printf '%s\n' "${fields[2]}"
}
proc_cmdline() {
    tr '\0' ' ' < "/proc/$1/cmdline" 2>/dev/null
}

stop_marked_pid() {
    local pid_file=$1 start_file=$2 marker=$3 group=${4:-no} pid start='' current command_line pgrp
    [[ -f "$pid_file" && ! -L "$pid_file" ]] || return 0
    pid=$(<"$pid_file")
    [[ "$pid" =~ ^[0-9]+$ && -r "/proc/$pid/cmdline" ]] || return 0
    command_line=$(proc_cmdline "$pid" || true)
    [[ "$command_line" == *"$marker"* ]] || return 0
    if [[ -f "$start_file" && ! -L "$start_file" ]]; then
        start=$(<"$start_file")
        [[ "$start" =~ ^[0-9]+$ ]] || { printf 'Owned process start marker is malformed.\n' >&2; return 1; }
        current=$(proc_start_ticks "$pid" 2>/dev/null || true)
        [[ "$current" == "$start" ]] || { printf 'Owned process PID identity changed before cleanup.\n' >&2; return 1; }
    fi
    if [[ "$group" == yes ]]; then
        pgrp=$(proc_pgrp "$pid" 2>/dev/null || true)
        [[ "$pgrp" == "$pid" ]] || { printf 'Refusing to leave children of an owned relay process group untracked.\n' >&2; return 1; }
        kill -TERM -- "-$pid" 2>/dev/null || true
        for _ in $(seq 1 30); do
            if ! kill -0 -- "-$pid" 2>/dev/null; then return 0; fi
            sleep 0.1
        done
        kill -KILL -- "-$pid" 2>/dev/null || true
        for _ in $(seq 1 20); do
            if ! kill -0 -- "-$pid" 2>/dev/null; then return 0; fi
            sleep 0.1
        done
        printf 'Could not stop owned relay process group %s.\n' "$pid" >&2
        return 1
    fi
    kill -TERM "$pid" 2>/dev/null || true
    for _ in $(seq 1 30); do
        [[ -r "/proc/$pid/cmdline" ]] || return 0
        current=$(proc_start_ticks "$pid" 2>/dev/null || true)
        [[ "$current" == "$start" || -z "$start" ]] || return 0
        sleep 0.1
    done
    current=$(proc_start_ticks "$pid" 2>/dev/null || true)
    if [[ "$current" == "$start" || -z "$start" ]]; then
        kill -KILL "$pid" 2>/dev/null || true
        for _ in $(seq 1 20); do
            [[ -r "/proc/$pid/cmdline" ]] || return 0
            current=$(proc_start_ticks "$pid" 2>/dev/null || true)
            [[ "$current" == "$start" || -z "$start" ]] || return 0
            sleep 0.1
        done
        printf 'Could not stop owned process %s.\n' "$pid" >&2
        return 1
    fi
}

stop_owned_guest() {
    local instance_id qemu_pid_file="$state_dir/qemu.pid" qemu_pid='' qemu_marker="$state_dir/guest.qcow2" qemu_name='' 
    if [[ -f "$state_dir/.instance" && ! -L "$state_dir/.instance" ]]; then
        instance_id=$(<"$state_dir/.instance")
        if [[ "$instance_id" =~ ^[[:alnum:]]{8}$ ]]; then
            qemu_name="dorothy-traefik-acceptance-$instance_id"
        fi
    fi
    stop_marked_pid "$state_dir/host-relay.pid" "$state_dir/host-relay.start" "$state_dir/ssh-relay.sock" yes
    stop_marked_pid "$state_dir/private-relay.pid" "$state_dir/private-relay.start" "$state_dir/ssh-relay.sock" yes
    stop_marked_pid "$state_dir/barrier-canary-dns.pid" "$state_dir/barrier-canary-dns.start" "$state_dir/barrier-canary-dns.pid" yes
    stop_marked_pid "$state_dir/barrier-canary-tcp4.pid" "$state_dir/barrier-canary-tcp4.start" "$state_dir/barrier-canary-tcp4.log" yes
    stop_marked_pid "$state_dir/barrier-canary-tcp6.pid" "$state_dir/barrier-canary-tcp6.start" "$state_dir/barrier-canary-tcp6.log" yes
    if [[ -f "$qemu_pid_file" && ! -L "$qemu_pid_file" ]]; then
        qemu_pid=$(<"$qemu_pid_file")
        if [[ "$qemu_pid" =~ ^[0-9]+$ && -r "/proc/$qemu_pid/cmdline" ]]; then
            local command_line start expected
            command_line=$(proc_cmdline "$qemu_pid" || true)
            expected='qemu-system-x86_64'
            if [[ "$command_line" == *"$expected"* && "$command_line" == *"$qemu_marker"* && ( -z "$qemu_name" || "$command_line" == *"$qemu_name"* ) ]]; then
                start=$(proc_start_ticks "$qemu_pid" 2>/dev/null || true)
                if [[ -f "$state_dir/network.identity" && ! -L "$state_dir/network.identity" ]]; then
                    local recorded_pid recorded_start
                    recorded_pid=$(awk -F= '$1 == "qemu_pid" { print substr($0, index($0, "=") + 1); exit }' "$state_dir/network.identity")
                    recorded_start=$(awk -F= '$1 == "qemu_start_ticks" { print substr($0, index($0, "=") + 1); exit }' "$state_dir/network.identity")
                    [[ "$recorded_pid" == "$qemu_pid" && "$recorded_start" == "$start" ]] || { printf 'QEMU pid identity changed before cleanup.\n' >&2; return 1; }
                fi
                kill -TERM "$qemu_pid" 2>/dev/null || true
                for _ in $(seq 1 50); do
                    [[ -r "/proc/$qemu_pid/cmdline" ]] || break
                    [[ "$(proc_start_ticks "$qemu_pid" 2>/dev/null || true)" == "$start" ]] || break
                    sleep 0.2
                done
                if [[ -r "/proc/$qemu_pid/cmdline" && "$(proc_start_ticks "$qemu_pid" 2>/dev/null || true)" == "$start" ]]; then
                    command_line=$(proc_cmdline "$qemu_pid" || true)
                    if [[ "$command_line" == *"$qemu_marker"* && ( -z "$qemu_name" || "$command_line" == *"$qemu_name"* ) ]]; then
                        kill -KILL "$qemu_pid" 2>/dev/null || true
                    fi
                fi
            fi
        fi
    fi
    if [[ ${qemu_pid:-} =~ ^[0-9]+$ && ${start:-} =~ ^[0-9]+$ ]]; then
        for _ in $(seq 1 20); do
            command_line=$(proc_cmdline "$qemu_pid" 2>/dev/null || true)
            if [[ "$command_line" != *"$qemu_marker"* || ( -n "$qemu_name" && "$command_line" != *"$qemu_name"* ) \
               || "$(proc_start_ticks "$qemu_pid" 2>/dev/null || true)" != "$start" ]]; then
                return 0
            fi
            sleep 0.1
        done
        printf 'Owned QEMU process %s remained alive after cleanup.\n' "$qemu_pid" >&2
        return 1
    fi
}

if [[ "$mode" == stop ]]; then
    stop_owned_guest
    exit 0
fi

[[ -f "$state_dir/.instance" && ! -L "$state_dir/.instance" ]] || { printf 'Acceptance state has no instance marker.\n' >&2; exit 2; }
instance_id=$(<"$state_dir/.instance")
[[ "$instance_id" =~ ^[[:alnum:]]{8}$ && "${state_dir##*.}" == "$instance_id" ]] || { printf 'Acceptance instance marker does not match the state path.\n' >&2; exit 2; }
[[ -f "$state_dir/network.identity" && ! -L "$state_dir/network.identity" ]] || { printf 'Network identity marker is missing or unsafe.\n' >&2; exit 2; }
[[ "$(stat -c %a "$state_dir/network.identity")" == 600 ]] || { printf 'Network identity marker permissions are not private.\n' >&2; exit 2; }

identity_value() {
    awk -F= -v key="$1" '$1 == key { print substr($0, index($0, "=") + 1); found=1; exit } END { if (!found) exit 1 }' "$state_dir/network.identity"
}
identity_instance=$(identity_value instance_id)
host_uid=$(identity_value host_uid)
host_netns_inode=$(identity_value host_netns_inode)
host_userns_inode=$(identity_value host_userns_inode)
qemu_pid=$(identity_value qemu_pid)
qemu_start=$(identity_value qemu_start_ticks)
netns_inode=$(identity_value netns_inode)
userns_inode=$(identity_value userns_inode)
uid_map=$(identity_value uid_map)
qemu_mac=$(identity_value qemu_mac)
private_ssh_port=$(identity_value private_ssh_port)
ssh_port=$(identity_value ssh_port)
backing_image_sha512=$(identity_value backing_image_sha512)
[[ "$identity_instance" == "$instance_id" ]] || { printf 'Network identity belongs to another guest.\n' >&2; exit 1; }
[[ "$host_uid" =~ ^[0-9]+$ && "$qemu_pid" =~ ^[0-9]+$ && "$qemu_start" =~ ^[0-9]+$ ]] || { printf 'Network identity contains malformed process identity.\n' >&2; exit 1; }
[[ "$host_netns_inode" =~ ^[0-9]+$ && "$netns_inode" =~ ^[0-9]+$ && "$host_userns_inode" =~ ^[0-9]+$ && "$userns_inode" =~ ^[0-9]+$ ]] || { printf 'Network identity contains malformed namespace identity.\n' >&2; exit 1; }
[[ "$ssh_port" =~ ^[0-9]+$ && "$private_ssh_port" =~ ^[0-9]+$ ]] || { printf 'Network identity contains malformed SSH relay ports.\n' >&2; exit 1; }
[[ "$qemu_mac" =~ ^52:54:00:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$ ]] || { printf 'Network identity contains a malformed QEMU MAC address.\n' >&2; exit 1; }
[[ "$backing_image_sha512" =~ ^[0-9a-f]{128}$ ]] || { printf 'Network identity contains an invalid backing-image digest.\n' >&2; exit 1; }

image_name=debian-13-generic-amd64-20261123-2671.qcow2
expected_image_sha512=562a4614952657a6ab8a89cda56eaf1bc85c8dfea51155184267bb6b6361eff215baf6afa2f8c2c8c2bad328ac6c30eead80664286ef4c8538368aeb7f87104f
[[ -f "$state_dir/$image_name" && ! -L "$state_dir/$image_name" ]] || { printf 'Pinned backing image is absent or unsafe.\n' >&2; exit 1; }
actual_image_sha512=$(sha512sum "$state_dir/$image_name" | awk '{ print $1 }')
[[ "$actual_image_sha512" == "$expected_image_sha512" && "$backing_image_sha512" == "$expected_image_sha512" ]] || { printf 'Pinned backing-image identity changed.\n' >&2; exit 1; }

[[ -f "$state_dir/qemu.pid" && ! -L "$state_dir/qemu.pid" && "$(<"$state_dir/qemu.pid")" == "$qemu_pid" ]] || { printf 'QEMU pid file does not match the network identity.\n' >&2; exit 1; }
[[ -r "/proc/$qemu_pid/cmdline" && -r "/proc/$qemu_pid/uid_map" ]] || { printf 'The owned QEMU process is not live.\n' >&2; exit 1; }
[[ "$(proc_start_ticks "$qemu_pid")" == "$qemu_start" ]] || { printf 'QEMU pid was reused or its process identity changed.\n' >&2; exit 1; }
[[ "$(stat -Lc %i "/proc/$qemu_pid/ns/net")" == "$netns_inode" && "$netns_inode" != "$host_netns_inode" ]] || { printf 'QEMU is not in its recorded isolated network namespace.\n' >&2; exit 1; }
[[ "$(stat -Lc %i "/proc/$qemu_pid/ns/user")" == "$userns_inode" && "$userns_inode" != "$host_userns_inode" ]] || { printf 'QEMU is not in its recorded unprivileged user namespace.\n' >&2; exit 1; }
[[ "$(stat -Lc %i /proc/self/ns/net)" == "$host_netns_inode" && "$(stat -Lc %i /proc/self/ns/user)" == "$host_userns_inode" ]] || { printf 'The checker is no longer in the host namespaces recorded at launch.\n' >&2; exit 1; }
[[ "$(awk '$1 == "Uid:" { print $2; exit }' "/proc/$qemu_pid/status")" == "$host_uid" ]] || { printf 'QEMU is not running as the mapped unprivileged host user.\n' >&2; exit 1; }
proc_uid_map=$(awk 'NF { printf "%s%s %s %s", (NR == 1 ? "" : ";"), $1, $2, $3 }' "/proc/$qemu_pid/uid_map")
[[ "$proc_uid_map" == "$uid_map" && "$uid_map" == "0 $host_uid 1" ]] || { printf 'QEMU uid mapping is not the expected unprivileged single-user mapping.\n' >&2; exit 1; }

qemu_name="dorothy-traefik-acceptance-$instance_id"
expected_netdev="user,id=net0,restrict=on,ipv6=off,hostfwd=tcp:127.0.0.1:$private_ssh_port-10.0.2.15:22"
declare -a qemu_argv
mapfile -d '' -t qemu_argv < "/proc/$qemu_pid/cmdline"
[[ "$(basename -- "${qemu_argv[0]}")" == qemu-system-x86_64 ]] || { printf 'Unexpected live QEMU executable.\n' >&2; exit 1; }
# Attest the complete launch vector. Checking only for the presence of an approved NIC
# would not rule out a second host channel (e.g. vsock, an inherited fd or a shared mount).
expected_argv=(
    -name "$qemu_name" -enable-kvm -machine q35 -cpu host -m 4096 -smp 2
    -drive "file=$state_dir/guest.qcow2,if=virtio,format=qcow2"
    -drive "file=$state_dir/seed.iso,media=cdrom,readonly=on"
    -netdev "$expected_netdev" -device "virtio-net-pci,netdev=net0,mac=$qemu_mac"
    -display none -serial "file:$state_dir/serial.log"
    -monitor "unix:$state_dir/qemu-monitor.sock,server=on,wait=off" -daemonize
    -pidfile "$state_dir/qemu.pid"
)
(( ${#qemu_argv[@]} == ${#expected_argv[@]} + 1 )) || { echo 'Unexpected extra or missing QEMU argument.' >&2; exit 1; }
for index in "${!expected_argv[@]}"; do
    [[ "${qemu_argv[index+1]}" == "${expected_argv[index]}" ]] || { echo 'Live QEMU arguments differ from the sealed launch contract.' >&2; exit 1; }
done

proxy_env=$(tr '\0' '\n' < "/proc/$qemu_pid/environ" | awk -F= 'tolower($1) ~ /^(http|https|all)_proxy$/ && $2 != "" { print $1 }')
[[ -z "$proxy_env" ]] || { printf 'QEMU inherited an effective proxy environment variable.\n' >&2; exit 1; }

links=$(awk 'NR > 2 { name=$1; sub(/:$/, "", name); print name }' "/proc/$qemu_pid/net/dev")
[[ "$links" == lo ]] || { printf 'The live QEMU network namespace has a non-loopback interface.\n' >&2; exit 1; }
routes4=$(awk 'NR > 1 && NF { destination=tolower($2); gateway=tolower($3); mask=tolower($8); if ($1 != "lo" || destination !~ /7f$/ || gateway != "00000000" || (mask != "000000ff" && mask != "ffffffff")) print }' "/proc/$qemu_pid/net/route")
routes6=$(awk 'NF >= 10 {
    zero="00000000000000000000000000000000"; dst=tolower($1); gw=tolower($5); dev=$10;
    # /proc exposes the kernel IPv6 null/reject sentinel; rtnetlink does not list it
    # as a usable default route. Accept only this exact zero-next-hop, metric-max encoding.
    reject=(dst==zero && $2=="00" && $3==zero && $4=="00" && gw==zero && tolower($6)=="ffffffff" && tolower($9)=="00200200" && dev=="lo");
    if (!reject && (dev!="lo" || gw!=zero || (dst!="00000000000000000000000000000001" && dst!~/^ff/))) print
}' "/proc/$qemu_pid/net/ipv6_route")
[[ -z "$routes4" && -z "$routes6" ]] || { printf 'The live QEMU namespace has a non-loopback IPv4 or IPv6 route.\n' >&2; exit 1; }

private_relay_pid=$(<"$state_dir/private-relay.pid")
host_relay_pid=$(<"$state_dir/host-relay.pid")
private_relay_start=$(<"$state_dir/private-relay.start")
host_relay_start=$(<"$state_dir/host-relay.start")
[[ "$private_relay_pid" =~ ^[0-9]+$ && "$host_relay_pid" =~ ^[0-9]+$ && "$private_relay_start" =~ ^[0-9]+$ && "$host_relay_start" =~ ^[0-9]+$ ]] || { printf 'SSH relay identity markers are malformed.\n' >&2; exit 1; }
[[ -r "/proc/$private_relay_pid/cmdline" && "$(proc_start_ticks "$private_relay_pid")" == "$private_relay_start" ]] || { printf 'Private SSH relay is not live with its recorded identity.\n' >&2; exit 1; }
[[ -r "/proc/$host_relay_pid/cmdline" && "$(proc_start_ticks "$host_relay_pid")" == "$host_relay_start" ]] || { printf 'Loopback SSH relay is not live with its recorded identity.\n' >&2; exit 1; }
private_relay_cmd=$(proc_cmdline "$private_relay_pid")
host_relay_cmd=$(proc_cmdline "$host_relay_pid")
[[ "$private_relay_cmd" == *"UNIX-LISTEN:$state_dir/ssh-relay.sock"* && "$private_relay_cmd" == *"TCP4:127.0.0.1:$private_ssh_port"* ]] || { printf 'Private SSH relay does not match its private socket/loopback target.\n' >&2; exit 1; }
[[ "$host_relay_cmd" == *"TCP4-LISTEN:$ssh_port,bind=127.0.0.1"* && "$host_relay_cmd" == *"UNIX-CONNECT:$state_dir/ssh-relay.sock"* ]] || { printf 'Host SSH relay is not bound only to loopback or does not use the private socket.\n' >&2; exit 1; }
[[ "$(stat -Lc %i "/proc/$private_relay_pid/ns/net")" == "$netns_inode" ]] || { printf 'Private SSH relay is outside the isolated QEMU network namespace.\n' >&2; exit 1; }
[[ -S "$state_dir/ssh-relay.sock" && "$(stat -c %a "$state_dir/ssh-relay.sock")" == 600 ]] || { printf 'Private SSH relay socket is absent or has unsafe permissions.\n' >&2; exit 1; }
ss -H -ltn "sport = :$ssh_port" | awk -v expected="127.0.0.1:$ssh_port" 'NF { count++; if ($4 != expected) bad=1 } END { exit !(count == 1 && !bad) }' || { printf 'SSH listener is not exactly one 127.0.0.1 listener.\n' >&2; exit 1; }

identity_sha256() {
    printf '%s\0' \
        'dorothy-traefik-acceptance-identity-v1' "$instance_id" "$host_uid" "$host_netns_inode" "$host_userns_inode" \
        "$qemu_pid" "$qemu_start" "$netns_inode" "$userns_inode" "$uid_map" \
        "$private_relay_pid" "$private_relay_start" "$host_relay_pid" "$host_relay_start" \
        "$backing_image_sha512" "$qemu_mac" "$ssh_port" "$private_ssh_port" \
        "$state_dir/guest.qcow2" "$state_dir/ssh-relay.sock" "127.0.0.1:$ssh_port" "$expected_netdev" \
        | sha256sum | awk '{ print $1 }'
}
current_identity_sha256=$(identity_sha256)

if [[ "$mode" == precondition ]]; then
    printf 'Fresh guest host isolation precondition passed.\n'
    exit 0
fi

receipt_path="$state_dir/barrier-receipt.json"
authorization_path="$state_dir/barrier-authorization.json"
required_checks='["host_namespace_isolated","qemu_backend_restricted","qemu_ipv6_disabled","host_routes_ipv4_empty","host_routes_ipv6_empty","qemu_proxy_environment_absent","guest_proxy_channels_absent","guest_default_routes_absent","guest_dns_upstreams_absent","guest_ntp_disabled","guest_ssh_forwarding_disabled","managed_dut_paths_absent","traefik_mainpid_absent","traefik_processes_absent","traefik_units_inactive","pebble_directory_verified","canary_host_ipv4_tcp_ready","canary_host_ipv6_tcp_ready","canary_host_ipv4_dns_udp_ready","canary_host_ipv4_dns_tcp_ready","canary_host_ipv6_dns_udp_ready","canary_host_ipv6_dns_tcp_ready","canary_guest_ipv4_tcp_blocked","canary_guest_ipv4_dns_udp_blocked","canary_guest_ipv4_dns_tcp_blocked","canary_guest_ipv6_tcp_blocked","canary_guest_ipv6_dns_udp_blocked","canary_guest_ipv6_dns_tcp_blocked"]'
validate_receipt() {
    [[ -f "$receipt_path" && ! -L "$receipt_path" && -s "$receipt_path" ]] || { printf 'Fresh guest barrier receipt is missing or unsafe.\n' >&2; return 1; }
    [[ "$(stat -c %a "$receipt_path")" == 600 && "$(stat -c %u "$receipt_path")" == "$(id -u)" ]] || { printf 'Barrier receipt is not owned and private.\n' >&2; return 1; }
    [[ -f "$state_dir/guest-files/pebble.minica.pem" && ! -L "$state_dir/guest-files/pebble.minica.pem" ]] || { printf 'Pinned Pebble fixture CA is missing.\n' >&2; return 1; }
    local pinned_ca_sha256
    pinned_ca_sha256=$(sha256sum "$state_dir/guest-files/pebble.minica.pem" | awk '{ print $1 }')
    jq -e --arg schema dorothy-traefik-acceptance-barrier-v1 \
        --arg identity "$current_identity_sha256" --arg image "$backing_image_sha512" \
        --arg ca "$pinned_ca_sha256" --argjson required "$required_checks" \
        '. as $r | .schema == $schema and .identity_sha256 == $identity and .backing_image_sha512 == $image
         and (.host_namespace | .interfaces == ["lo"] and .ipv4_nonlocal_routes == [] and .ipv6_nonlocal_routes == []
              and .qemu_backend_restricted == true and .qemu_ipv6_disabled == true and .proxy_environment_absent == true)
         and (.guest | .traefik_processes == 0 and .active_traefik_units == [] and .traefik_unit_files == []
              and .proxy_channels_absent == true and .ipv6_loopback_ready == true)
         and (.guest.pebble_directory | .primary_http_status == 200 and .rotated_http_status == 200 and .ca_sha256 == $ca
              and (.primary_response_sha256 | test("^[0-9a-f]{64}$")) and (.rotated_response_sha256 | test("^[0-9a-f]{64}$")))
         and (.canary as $c | all(["ipv4_tcp","ipv6_tcp","ipv4_dns_udp","ipv4_dns_tcp","ipv6_dns_udp","ipv6_dns_tcp"][];
                                  . as $kind | $c["host_"+$kind] == "ready" and $c["guest_"+$kind] == "blocked"))
         and .canary.target_addresses == ["10.0.2.2","2001:db8::1"]
         and all($required[]; $r.checks[.] == true)' \
        "$receipt_path" >/dev/null || { printf 'Fresh guest barrier receipt does not match the live guest identity or a required success check.\n' >&2; return 1; }
    jq -e '.guest.default_routes_absent == true and .guest.dns_upstreams_absent == true and .guest.ntp_disabled == true and .guest.ssh_forwarding_disabled == true and .guest.managed_mainpid == 0 and .guest.managed_dut_paths_absent == true and .canary.server_logged_host_dns_positive == true and .canary.server_received_guest_dns_query == false' \
    "$receipt_path" >/dev/null || { printf 'Fresh guest receipt does not prove the guest has no outside route/DNS/NTP or managed Traefik DUT.\n' >&2; return 1; }
}


if [[ "$mode" == acceptance || "$mode" == authorize ]]; then
    validate_receipt || exit 1
    if [[ "$mode" == authorize ]]; then
        jq -e '.authorization_gate.pre_authorization_acceptance == "blocked"' "$receipt_path" >/dev/null \
            || { printf 'Receipt lacks proof that acceptance was blocked before explicit authorization.\n' >&2; exit 1; }
        [[ ! -e "$authorization_path" && ! -L "$authorization_path" ]] || { printf 'Barrier authorization already exists; refusing to overwrite it.\n' >&2; exit 1; }
        actual_receipt_sha256=$(sha256sum "$receipt_path" | awk '{ print $1 }')
        [[ "$reviewed_receipt_sha256" == "$actual_receipt_sha256" ]] || { printf 'Reviewed receipt digest does not match the current receipt.\n' >&2; exit 1; }
        authorization_tmp="$authorization_path.tmp.$RANDOM"
        jq -n --arg schema dorothy-traefik-acceptance-barrier-authorization-v1 \
            --arg authorized_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            --arg receipt_sha256 "$actual_receipt_sha256" --arg identity_sha256 "$current_identity_sha256" \
            --arg backing_image_sha512 "$backing_image_sha512" \
            '{schema:$schema,authorized_at_utc:$authorized_at_utc,receipt_sha256:$receipt_sha256,identity_sha256:$identity_sha256,backing_image_sha512:$backing_image_sha512}' \
            > "$authorization_tmp"
        chmod 600 "$authorization_tmp"
        jq -e . "$authorization_tmp" >/dev/null
        mv -- "$authorization_tmp" "$authorization_path"
        chmod 600 "$authorization_path"
        printf 'Recorded independent-review authorization for receipt SHA-256 %s.\n' "$actual_receipt_sha256"
        exit 0
    fi
    [[ -f "$authorization_path" && ! -L "$authorization_path" && -s "$authorization_path" ]] || { printf 'Fresh guest receipt has not been explicitly authorized after independent review.\n' >&2; exit 1; }
    [[ "$(stat -c %a "$authorization_path")" == 600 && "$(stat -c %u "$authorization_path")" == "$(id -u)" ]] || { printf 'Barrier authorization marker is not owned and private.\n' >&2; exit 1; }
    jq -e '.authorization_gate.pre_authorization_acceptance == "blocked"' "$receipt_path" >/dev/null \
        || { printf 'Receipt lacks proof that acceptance was blocked before explicit authorization.\n' >&2; exit 1; }
    receipt_sha256=$(sha256sum "$receipt_path" | awk '{ print $1 }')
    jq -e --arg schema dorothy-traefik-acceptance-barrier-authorization-v1 \
        --arg receipt "$receipt_sha256" --arg identity "$current_identity_sha256" --arg image "$backing_image_sha512" \
        '.schema == $schema and .receipt_sha256 == $receipt and .identity_sha256 == $identity and .backing_image_sha512 == $image' \
        "$authorization_path" >/dev/null || { printf 'Barrier authorization marker does not authorize the current VM and exact reviewed receipt.\n' >&2; exit 1; }
    printf 'Fresh guest barrier receipt is authorized for the current VM; isolation checks passed.\n'
    exit 0
fi

[[ "$mode" == receipt ]] || usage
[[ ! -e "$receipt_path" && ! -L "$receipt_path" ]] || { printf 'Refusing to overwrite an existing fresh guest barrier receipt.\n' >&2; exit 1; }
[[ ! -e "$authorization_path" && ! -L "$authorization_path" ]] || { printf 'Refusing receipt creation over an existing authorization marker.\n' >&2; exit 1; }
for command in jq sha256sum dig dnsmasq socat ss timeout; do
    command -v "$command" >/dev/null || { printf 'Missing required host barrier-check command: %s\n' "$command" >&2; exit 2; }
done
[[ -x /usr/bin/ssh ]] || { printf 'Missing required host barrier-check command: /usr/bin/ssh\n' >&2; exit 2; }
[[ -f "$state_dir/handle.env" && ! -L "$state_dir/handle.env" && "$(stat -c %a "$state_dir/handle.env")" == 600 ]] || { printf 'SSH handle is missing or unsafe.\n' >&2; exit 1; }
# handle.env is created by prepare.sh and extended by prepare-services.sh inside this private directory.
source "$state_dir/handle.env"
[[ "${SSH_HOST:-}" == 127.0.0.1 && "${SSH_PORT:-}" == "$ssh_port" && "${SSH_USER:-}" == root \
   && "${SSH_CONFIG:-}" == "$state_dir/ssh_config" && "${SSH_IDENTITY:-}" == "$state_dir/id_ed25519" \
   && -f "$SSH_CONFIG" && ! -L "$SSH_CONFIG" && "$(stat -c %a "$SSH_CONFIG")" == 600 \
   && -f "$SSH_IDENTITY" && ! -L "$SSH_IDENTITY" && "$(stat -c %a "$SSH_IDENTITY")" == 600 ]] \
    || { printf 'SSH handle does not match the recorded private relay.\n' >&2; exit 1; }
if grep -Eq '^[[:space:]]*(ProxyCommand|ProxyJump)[[:space:]]+' "$SSH_CONFIG"; then
    printf 'SSH control configuration has an unexpected proxy path.\n' >&2
    exit 1
fi
[[ "${GUEST_ROOT:-}" =~ ^/var/tmp/dorothy-traefik-acceptance\.[[:alnum:]]+$ ]] || { printf 'prepare-services has not recorded an owned guest fixture root.\n' >&2; exit 1; }
[[ -f "$state_dir/guest-files/pebble.minica.pem" && ! -L "$state_dir/guest-files/pebble.minica.pem" ]] || { printf 'Pinned Pebble fixture CA is missing.\n' >&2; exit 1; }
expected_ca_sha256=$(sha256sum "$state_dir/guest-files/pebble.minica.pem" | awk '{ print $1 }')
[[ "$expected_ca_sha256" =~ ^[0-9a-f]{64}$ ]] || { printf 'Pinned Pebble fixture CA digest is malformed.\n' >&2; exit 1; }

canary_instance="barrier-${instance_id,,}.dorothy.test"
positive_name="host-positive.$canary_instance"
guest_name="guest-probe.$canary_instance"
canary_token="dorothy-canary-$instance_id"
canary_ipv4=10.0.2.2
canary_ipv6=2001:db8::1
choose_local_port() {
    local candidate
    for _ in $(seq 1 200); do
        candidate=$((30000 + RANDOM % 30000))
        if ! ss -H -ltn "sport = :$candidate" | grep -q . && ! ss -H -lun "sport = :$candidate" | grep -q .; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}
canary_dns_port=$(choose_local_port) || { printf 'Could not allocate a private DNS canary port.\n' >&2; exit 1; }
canary_tcp_port=$(choose_local_port) || { printf 'Could not allocate a private TCP canary port.\n' >&2; exit 1; }

cleanup_canaries() {
    stop_marked_pid "$state_dir/barrier-canary-dns.pid" "$state_dir/barrier-canary-dns.start" "$state_dir/barrier-canary-dns.pid" yes
    stop_marked_pid "$state_dir/barrier-canary-tcp4.pid" "$state_dir/barrier-canary-tcp4.start" "$state_dir/barrier-canary-tcp4.log" yes
    stop_marked_pid "$state_dir/barrier-canary-tcp6.pid" "$state_dir/barrier-canary-tcp6.start" "$state_dir/barrier-canary-tcp6.log" yes
}
trap cleanup_canaries EXIT
trap 'cleanup_canaries; exit 130' INT
trap 'cleanup_canaries; exit 143' TERM

start_canary_process() {
    local pid_file=$1 start_file=$2 log_file=$3 marker=$4
    shift 4
    setsid --fork /bin/sh -c 'umask 077; printf "%s\n" "$$" > "$1"; shift; exec "$@"' \
        sh "$pid_file" "$@" </dev/null > "$log_file" 2>&1
    local pid=''
    for _ in $(seq 1 50); do
        [[ -s "$pid_file" ]] || { sleep 0.05; continue; }
        pid=$(<"$pid_file")
        [[ "$pid" =~ ^[0-9]+$ ]] || continue
        if [[ -r "/proc/$pid/cmdline" ]]; then
            local command_line start
            command_line=$(proc_cmdline "$pid" || true)
            if [[ "$command_line" == *"$marker"* ]]; then
                start=$(proc_start_ticks "$pid" 2>/dev/null || true)
                if [[ "$start" =~ ^[0-9]+$ ]]; then
                    printf '%s\n' "$start" > "$start_file"
                    chmod 600 "$start_file"
                    return 0
                fi
            fi
        fi
        sleep 0.05
    done
    printf 'Private host canary failed to start: %s\n' "$marker" >&2
    return 1
}

start_canary_process "$state_dir/barrier-canary-dns.pid" "$state_dir/barrier-canary-dns.start" \
    "$state_dir/barrier-canary-dns.log" "--pid-file=$state_dir/barrier-canary-dns.pid" \
    dnsmasq --no-daemon --conf-file=/dev/null --no-resolv --no-hosts --interface=lo --bind-interfaces \
    --listen-address=127.0.0.1 --listen-address=::1 --port="$canary_dns_port" \
    --address="/$canary_instance/$canary_ipv4" --address="/$canary_instance/$canary_ipv6" \
    --log-queries=extra --log-facility=- \
    --pid-file="$state_dir/barrier-canary-dns.pid"
start_canary_process "$state_dir/barrier-canary-tcp4.pid" "$state_dir/barrier-canary-tcp4.start" \
    "$state_dir/barrier-canary-tcp4.log" "$state_dir/barrier-canary-tcp4.log" \
    socat -lf "$state_dir/barrier-canary-tcp4.log" \
    "TCP4-LISTEN:$canary_tcp_port,bind=127.0.0.1,reuseaddr,fork" "EXEC:/bin/echo $canary_token"
start_canary_process "$state_dir/barrier-canary-tcp6.pid" "$state_dir/barrier-canary-tcp6.start" \
    "$state_dir/barrier-canary-tcp6.log" "$state_dir/barrier-canary-tcp6.log" \
    socat -lf "$state_dir/barrier-canary-tcp6.log" \
    "TCP6-LISTEN:$canary_tcp_port,bind=::1,reuseaddr,fork" "EXEC:/bin/echo $canary_token"

for _ in $(seq 1 50); do
    [[ -n "$(ss -H -lun "sport = :$canary_dns_port")" && -n "$(ss -H -ltn "sport = :$canary_dns_port")" \
       && -n "$(ss -H -ltn "sport = :$canary_tcp_port")" ]] && break
    sleep 0.05
done

canary_listener_check() {
    local port=$1 protocol=$2 expected4="127.0.0.1:$1" expected6="[::1]:$1"
    local listeners
    if [[ "$protocol" == udp ]]; then
        listeners=$(ss -H -lun "sport = :$port")
    else
        listeners=$(ss -H -ltn "sport = :$port")
    fi
    awk -v expected4="$expected4" -v expected6="$expected6" '
        NF { count++; if ($4 != expected4 && $4 != expected6) bad=1; if ($4 == expected4) v4=1; if ($4 == expected6) v6=1 }
        END { exit !(count == 2 && !bad && v4 && v6) }' <<< "$listeners"
}
canary_listener_check "$canary_dns_port" udp && canary_listener_check "$canary_dns_port" tcp \
    || { printf 'Private DNS canary is not bound only on host loopback in both families.\n' >&2; exit 1; }
canary_listener_check "$canary_tcp_port" tcp \
    || { printf 'Private TCP canary is not bound only on host loopback in both families.\n' >&2; exit 1; }

host_dns_probe() {
    local family=$1 transport=$2 qtype=$3 expected=$4 server
    if [[ "$family" == 4 ]]; then server=127.0.0.1; else server=::1; fi
    local -a transport_args=()
    [[ "$transport" == tcp ]] && transport_args+=(+tcp)
    result=$(dig "-$family" +time=1 +tries=1 +short "${transport_args[@]}" "@$server" -p "$canary_dns_port" "$positive_name" "$qtype")
    [[ "$result" == "$expected" ]]
}
host_tcp_probe() {
    local family=$1 server output
    if [[ "$family" == 4 ]]; then
        output=$(timeout 3 socat - "TCP4:127.0.0.1:$canary_tcp_port")
    else
        output=$(timeout 3 socat - "TCP6:[::1]:$canary_tcp_port")
    fi
    [[ "$output" == "$canary_token" ]]
}
for family in 4 6; do
    host_tcp_probe "$family" || { printf 'Private host TCP canary failed its positive readiness probe (IPv%s).\n' "$family" >&2; exit 1; }
    for transport in udp tcp; do
        host_dns_probe "$family" "$transport" A "$canary_ipv4" || { printf 'Private host DNS A canary failed its positive readiness probe (IPv%s %s).\n' "$family" "$transport" >&2; exit 1; }
        host_dns_probe "$family" "$transport" AAAA "$canary_ipv6" || { printf 'Private host DNS AAAA canary failed its positive readiness probe (IPv%s %s).\n' "$family" "$transport" >&2; exit 1; }
    done
done

remote_result=$(/usr/bin/ssh -F "$SSH_CONFIG" -p "$SSH_PORT" "$SSH_USER@$SSH_HOST" \
    "bash -s -- '$GUEST_ROOT' '$canary_dns_port' '$canary_tcp_port' '$guest_name' '$expected_ca_sha256' '$canary_ipv4' '$canary_ipv6' '$canary_token'" <<'REMOTE'
set -euo pipefail
root=$1
dns_port=$2
tcp_port=$3
domain=$4
expected_ca_sha256=$5
canary_ipv4=$6
canary_ipv6=$7
canary_token=$8

[[ -d "$root" && ! -L "$root" && "$(realpath -e -- "$root")" == "$root" ]] || { printf 'Guest fixture root is absent or unsafe.\n' >&2; exit 1; }
[[ "$(<"$root/.owner")" == dorothy-traefik-acceptance-guest-v1 ]] || { printf 'Guest fixture ownership marker does not match.\n' >&2; exit 1; }

traefik_processes=0
for comm_file in /proc/[0-9]*/comm; do
    [[ -r "$comm_file" ]] || continue
    IFS= read -r process_comm < "$comm_file" || continue
    [[ "${process_comm,,}" == traefik ]] && ((traefik_processes += 1))
done
active_traefik_units=$(systemctl list-units --all --type=service --state=active --no-legend --plain \
    | awk 'tolower($1) ~ /(^|[-.])traefik(@[^[:space:]]*)?\.(service|socket|target|timer)$/ { print $1 }')
traefik_unit_files=$(systemctl list-unit-files --no-legend --no-pager \
    | awk 'tolower($1) ~ /(^|[-.])traefik(@[^[:space:]]*)?\.(service|socket|target|timer)$/ { print $1 }')
[[ "$traefik_processes" == 0 && -z "$active_traefik_units" && -z "$traefik_unit_files" ]] || {
    printf 'Traefik is running or a Traefik service/unit is installed or active.\n' >&2
    exit 1
}
managed_mainpid=$(systemctl show --property=MainPID --value keroosha-traefik.service 2>/dev/null || true)
[[ -n "$managed_mainpid" ]] || managed_mainpid=0
[[ "$managed_mainpid" == 0 ]] || { printf 'Managed Traefik MainPID is running.\n' >&2; exit 1; }
[[ ! -e /etc/systemd/system/keroosha-traefik.service && ! -L /etc/systemd/system/keroosha-traefik.service \
   && ! -e /etc/keroosha-iac/traefik/static.yml && ! -L /etc/keroosha-iac/traefik/static.yml \
   && ! -e /etc/keroosha-iac/traefik && ! -L /etc/keroosha-iac/traefik \
   && ! -e /var/lib/keroosha-traefik && ! -L /var/lib/keroosha-traefik ]] || {
    printf 'Managed Traefik unit, configuration, or ACME store is present.\n' >&2
    exit 1
}
managed_dut_paths_absent=true

has_proxy_environment() {
    env | awk -F= 'tolower($1) ~ /^(http|https|all)_proxy$/ && $2 != "" { found=1 } END { exit !found }'
}
systemd_environment=$(systemctl show-environment) || { printf 'Cannot inspect the guest systemd environment.\n' >&2; exit 1; }
proxy_config_paths=()
for path in /etc/environment /etc/profile /etc/profile.d /etc/apt/apt.conf /etc/apt/apt.conf.d; do
    [[ -e "$path" ]] && proxy_config_paths+=("$path")
done
if has_proxy_environment \
   || printf '%s\n' "$systemd_environment" | awk -F= 'tolower($1) ~ /^(http|https|all)_proxy$/ && $2 != "" { found=1 } END { exit !found }' \
   || { ((${#proxy_config_paths[@]})) && grep -RqiE '^[[:space:]]*(export[[:space:]]+)?(http|https|all)_proxy[[:space:]]*=|Acquire::(http|https)::Proxy[[:space:]]' "${proxy_config_paths[@]}"; }; then
    printf 'Guest has an effective proxy channel.\n' >&2
    exit 1
fi
default_route4=$(ip -4 route show default)
default_route6=$(ip -6 route show default)
[[ -z "$default_route4" && -z "$default_route6" ]] || { printf 'Guest has an IPv4 or IPv6 default route.\n' >&2; exit 1; }
if grep -Eq '^[[:space:]]*nameserver[[:space:]]+' /etc/resolv.conf; then
    printf 'Guest has a configured DNS upstream.\n' >&2
    exit 1
fi
nonloopback_v6_routes=$(ip -6 route show table all | awk '$0 !~ /dev lo([[:space:]]|$)/ { print }')
[[ -z "$nonloopback_v6_routes" ]] || { printf 'Guest has a non-loopback IPv6 route.\n' >&2; exit 1; }
if ip -6 addr show dev isolated0 scope global | grep -q .; then
    printf 'Guest has a non-loopback global IPv6 address.\n' >&2
    exit 1
fi
sshd_settings=$(sshd -T) || { printf 'Cannot inspect effective guest sshd configuration.\n' >&2; exit 1; }
printf '%s\n' "$sshd_settings" | awk '
    $1 == "disableforwarding" && $2 == "yes" { disabled=1 }
    $1 == "allowtcpforwarding" && $2 == "no" { tcp=1 }
    $1 == "allowstreamlocalforwarding" && $2 == "no" { streamlocal=1 }
    $1 == "allowagentforwarding" && $2 == "no" { agent=1 }
    $1 == "x11forwarding" && $2 == "no" { x11=1 }
    $1 == "permittunnel" && $2 == "no" { tunnel=1 }
    $1 == "gatewayports" && $2 == "no" { gateway=1 }
    END { exit !(disabled && tcp && streamlocal && agent && x11 && tunnel && gateway) }' \
    || { printf 'Guest SSH forwarding is not fully disabled.\n' >&2; exit 1; }
timesyncd_state=$(systemctl is-active systemd-timesyncd.service 2>/dev/null || true)
resolved_state=$(systemctl is-active systemd-resolved.service 2>/dev/null || true)
[[ "$timesyncd_state" != active && "$resolved_state" != active ]] || { printf 'Guest time or DNS service is still active.\n' >&2; exit 1; }
guest_default_routes_absent=true
guest_dns_upstreams_absent=true
guest_ntp_disabled=true
guest_ssh_forwarding_disabled=true

ca_sha256=$(sha256sum "$root/certs/pebble.minica.pem" | awk '{ print $1 }')
[[ "$ca_sha256" == "$expected_ca_sha256" ]] || { printf 'Guest Pebble CA does not match the pinned staged fixture CA.\n' >&2; exit 1; }
ip -6 addr show dev lo | grep -Eq 'inet6 ::1/128 scope host' || { printf 'Guest IPv6 loopback ::1 is unavailable.\n' >&2; exit 1; }
primary_directory_path="$root/logs/barrier-pebble-directory.json"
primary_http_status=$(curl --noproxy '*' --resolve localhost:14000:127.0.0.1 --fail --silent --show-error --cacert "$root/certs/pebble.minica.pem" \
    --output "$primary_directory_path" --write-out '%{http_code}' https://localhost:14000/dir)
rotated_directory_path="$root/logs/barrier-pebble-rotated-directory.json"
rotated_http_status=$(curl --noproxy '*' --resolve localhost:14001:127.0.0.1 --fail --silent --show-error --cacert "$root/certs/pebble.minica.pem" \
    --output "$rotated_directory_path" --write-out '%{http_code}' https://localhost:14001/dir)
[[ "$primary_http_status" == 200 && "$rotated_http_status" == 200 ]] || { printf 'Pebble issuer directories did not both return HTTP 200.\n' >&2; exit 1; }
verify_directory() {
    local path=$1 port=$2
    jq -e --arg prefix "https://localhost:$port/" '. as $doc | all(["newNonce","newAccount","newOrder","revokeCert","keyChange"][]; ($doc[.] | type == "string" and startswith($prefix))) and (if ($doc | has("renewalInfo")) then ($doc.renewalInfo | type == "string" and startswith($prefix)) else true end)' \
        "$path" >/dev/null
}
verify_directory "$primary_directory_path" 14000 || { printf 'Primary Pebble issuer directory response is incomplete.\n' >&2; exit 1; }
verify_directory "$rotated_directory_path" 14001 || { printf 'Rotated Pebble issuer directory response is incomplete.\n' >&2; exit 1; }
primary_directory_sha256=$(sha256sum "$primary_directory_path" | awk '{ print $1 }')
rotated_directory_sha256=$(sha256sum "$rotated_directory_path" | awk '{ print $1 }')

blocked_dns_probe() {
    local family=$1 transport=$2 server=$3 qtype=$4 result status=0
    local -a transport_args=()
    [[ "$transport" == tcp ]] && transport_args+=(+tcp)
    result=$(LC_ALL=C dig "-$family" +time=1 +tries=1 +comments "${transport_args[@]}" \
        "@$server" -p "$dns_port" "$domain" "$qtype" 2>&1) || status=$?
    # dig writes timeout messages on stdout. A DNS reply, even NXDOMAIN or
    # REFUSED, is reachability, not a passing negative. BIND exit 9 is no reply.
    [[ "$status" == 9 && "$result" == *"no servers could be reached"* && "$result" != *"status: "* ]]
}
blocked_tcp_probe() {
    local family=$1 server=$2
    ! timeout 2 nc "-$family" -z -w 1 "$server" "$tcp_port" >/dev/null 2>&1
}

blocked_tcp_probe 4 "$canary_ipv4" || { printf 'Guest reached the private IPv4 TCP canary path.\n' >&2; exit 1; }
for transport in udp tcp; do
    for qtype in A AAAA; do
        blocked_dns_probe 4 "$transport" "$canary_ipv4" "$qtype" || { printf 'Guest reached the private IPv4 DNS canary path.\n' >&2; exit 1; }
    done
done
blocked_tcp_probe 6 "$canary_ipv6" || { printf 'Guest reached the private IPv6 TCP canary path.\n' >&2; exit 1; }
for transport in udp tcp; do
    for qtype in A AAAA; do
        blocked_dns_probe 6 "$transport" "$canary_ipv6" "$qtype" || { printf 'Guest reached the private IPv6 DNS canary path.\n' >&2; exit 1; }
    done
done

printf 'traefik_processes=%s\n' "$traefik_processes"
printf 'active_traefik_units=%s\n' "${active_traefik_units//$'\n'/,}"
printf 'traefik_unit_files=%s\n' "${traefik_unit_files//$'\n'/,}"
printf 'managed_mainpid=%s\nmanaged_dut_paths_absent=true\n' "$managed_mainpid"
printf 'guest_proxy_channels_absent=true\n'
printf 'guest_default_routes_absent=true\nguest_dns_upstreams_absent=true\nguest_ntp_disabled=true\nguest_ssh_forwarding_disabled=true\n'
printf 'guest_ipv6_loopback_ready=true\n'
printf 'primary_http_status=%s\nrotated_http_status=%s\n' "$primary_http_status" "$rotated_http_status"
printf 'pebble_ca_sha256=%s\n' "$ca_sha256"
printf 'primary_directory_sha256=%s\nrotated_directory_sha256=%s\n' "$primary_directory_sha256" "$rotated_directory_sha256"
printf 'guest_ipv4_tcp=blocked\nguest_ipv4_dns_udp=blocked\nguest_ipv4_dns_tcp=blocked\n'
printf 'guest_ipv6_tcp=blocked\nguest_ipv6_dns_udp=blocked\nguest_ipv6_dns_tcp=blocked\n'
REMOTE
)
grep -Fq "$positive_name" "$state_dir/barrier-canary-dns.log" || { echo 'Host DNS canary failed to log its positive control.' >&2; exit 1; }
if grep -Fq "$guest_name" "$state_dir/barrier-canary-dns.log"; then
    echo 'The private host DNS canary received a guest query.' >&2; exit 1
fi
printf '%s\n' "$remote_result" > "$state_dir/guest-barrier-check.log"
chmod 600 "$state_dir/guest-barrier-check.log"
value_from_guest() {
    awk -F= -v key="$1" '$1 == key { print substr($0, index($0, "=") + 1); found=1; exit } END { if (!found) exit 1 }' <<< "$remote_result"
}
[[ "$(value_from_guest traefik_processes)" == 0 ]] || { printf 'Guest Traefik process check failed.\n' >&2; exit 1; }
[[ -z "$(value_from_guest active_traefik_units)" && -z "$(value_from_guest traefik_unit_files)" ]] || { printf 'Guest Traefik unit check failed.\n' >&2; exit 1; }
[[ "$(value_from_guest guest_proxy_channels_absent)" == true ]] || { printf 'Guest proxy channel check failed.\n' >&2; exit 1; }
[[ "$(value_from_guest guest_ipv6_loopback_ready)" == true ]] || { printf 'Guest IPv6 loopback check failed.\n' >&2; exit 1; }
managed_mainpid=$(value_from_guest managed_mainpid)
[[ "$managed_mainpid" == 0 && "$(value_from_guest managed_dut_paths_absent)" == true ]] || { printf 'Managed Traefik DUT is present.\n' >&2; exit 1; }
for check in guest_default_routes_absent guest_dns_upstreams_absent guest_ntp_disabled guest_ssh_forwarding_disabled; do
    [[ "$(value_from_guest "$check")" == true ]] || { printf 'Guest external-channel check failed: %s\n' "$check" >&2; exit 1; }
done
primary_http_status=$(value_from_guest primary_http_status)
rotated_http_status=$(value_from_guest rotated_http_status)
pebble_ca_sha256=$(value_from_guest pebble_ca_sha256)
primary_directory_sha256=$(value_from_guest primary_directory_sha256)
rotated_directory_sha256=$(value_from_guest rotated_directory_sha256)
[[ "$primary_http_status" == 200 && "$rotated_http_status" == 200 && "$pebble_ca_sha256" == "$expected_ca_sha256" \
   && "$primary_directory_sha256" =~ ^[0-9a-f]{64}$ && "$rotated_directory_sha256" =~ ^[0-9a-f]{64}$ ]] \
    || { printf 'Guest Pebble issuer directory evidence is incomplete.\n' >&2; exit 1; }
for check in guest_ipv4_tcp guest_ipv4_dns_udp guest_ipv4_dns_tcp guest_ipv6_tcp guest_ipv6_dns_udp guest_ipv6_dns_tcp; do
    [[ "$(value_from_guest "$check")" == blocked ]] || { printf 'Guest private-canary path was not blocked: %s\n' "$check" >&2; exit 1; }
done

checks=$(jq -n \
    --argjson host_namespace_isolated true --argjson qemu_backend_restricted true --argjson qemu_ipv6_disabled true \
    --argjson host_routes_ipv4_empty true --argjson host_routes_ipv6_empty true --argjson qemu_proxy_environment_absent true \
    --argjson guest_proxy_channels_absent true --argjson guest_ipv6_loopback_ready true \
    --argjson traefik_processes_absent true --argjson traefik_units_inactive true \
    --argjson pebble_directory_verified true --argjson canary_host_ipv4_tcp_ready true --argjson canary_host_ipv6_tcp_ready true \
    --argjson canary_host_ipv4_dns_udp_ready true --argjson canary_host_ipv4_dns_tcp_ready true \
    --argjson canary_host_ipv6_dns_udp_ready true --argjson canary_host_ipv6_dns_tcp_ready true \
    --argjson canary_guest_ipv4_tcp_blocked true --argjson canary_guest_ipv4_dns_udp_blocked true \
    --argjson canary_guest_ipv4_dns_tcp_blocked true --argjson canary_guest_ipv6_tcp_blocked true \
    --argjson canary_guest_ipv6_dns_udp_blocked true --argjson canary_guest_ipv6_dns_tcp_blocked true \
    '{host_namespace_isolated:$host_namespace_isolated,qemu_backend_restricted:$qemu_backend_restricted,qemu_ipv6_disabled:$qemu_ipv6_disabled,host_routes_ipv4_empty:$host_routes_ipv4_empty,host_routes_ipv6_empty:$host_routes_ipv6_empty,qemu_proxy_environment_absent:$qemu_proxy_environment_absent,guest_proxy_channels_absent:$guest_proxy_channels_absent,guest_ipv6_loopback_ready:$guest_ipv6_loopback_ready,traefik_processes_absent:$traefik_processes_absent,traefik_units_inactive:$traefik_units_inactive,pebble_directory_verified:$pebble_directory_verified,canary_host_ipv4_tcp_ready:$canary_host_ipv4_tcp_ready,canary_host_ipv6_tcp_ready:$canary_host_ipv6_tcp_ready,canary_host_ipv4_dns_udp_ready:$canary_host_ipv4_dns_udp_ready,canary_host_ipv4_dns_tcp_ready:$canary_host_ipv4_dns_tcp_ready,canary_host_ipv6_dns_udp_ready:$canary_host_ipv6_dns_udp_ready,canary_host_ipv6_dns_tcp_ready:$canary_host_ipv6_dns_tcp_ready,canary_guest_ipv4_tcp_blocked:$canary_guest_ipv4_tcp_blocked,canary_guest_ipv4_dns_udp_blocked:$canary_guest_ipv4_dns_udp_blocked,canary_guest_ipv4_dns_tcp_blocked:$canary_guest_ipv4_dns_tcp_blocked,canary_guest_ipv6_tcp_blocked:$canary_guest_ipv6_tcp_blocked,canary_guest_ipv6_dns_udp_blocked:$canary_guest_ipv6_dns_udp_blocked,canary_guest_ipv6_dns_tcp_blocked:$canary_guest_ipv6_dns_tcp_blocked}')
checks=$(jq '. + {guest_default_routes_absent:true,guest_dns_upstreams_absent:true,guest_ntp_disabled:true,guest_ssh_forwarding_disabled:true,managed_dut_paths_absent:true,traefik_mainpid_absent:true}' <<< "$checks")

receipt_tmp="$state_dir/barrier-receipt.json.tmp.$RANDOM"
jq -n \
    --arg schema dorothy-traefik-acceptance-barrier-v1 \
    --arg checked_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg identity_sha256 "$current_identity_sha256" \
    --arg backing_image_sha512 "$backing_image_sha512" \
    --arg netns_identity_sha256 "$(printf '%s\0' "$host_netns_inode" "$netns_inode" "$userns_inode" "$uid_map" | sha256sum | awk '{ print $1 }')" \
    --arg host_uid_map_sha256 "$(printf '%s' "$uid_map" | sha256sum | awk '{ print $1 }')" \
    --arg ca_sha256 "$pebble_ca_sha256" \
    --arg primary_directory_sha256 "$primary_directory_sha256" \
    --arg rotated_directory_sha256 "$rotated_directory_sha256" \
    --argjson primary_http_status "$primary_http_status" \
    --argjson rotated_http_status "$rotated_http_status" \
    --argjson checks "$checks" \
    '{schema:$schema,checked_at_utc:$checked_at_utc,identity_sha256:$identity_sha256,backing_image_sha512:$backing_image_sha512,host_namespace:{netns_identity_sha256:$netns_identity_sha256,uid_map_sha256:$host_uid_map_sha256,interfaces:["lo"],ipv4_nonlocal_routes:[],ipv6_nonlocal_routes:[],qemu_backend_restricted:true,qemu_ipv6_disabled:true,proxy_environment_absent:true},guest:{traefik_processes:0,active_traefik_units:[],traefik_unit_files:[],proxy_channels_absent:true,ipv6_loopback_ready:true,pebble_directory:{primary_http_status:$primary_http_status,rotated_http_status:$rotated_http_status,ca_sha256:$ca_sha256,primary_response_sha256:$primary_directory_sha256,rotated_response_sha256:$rotated_directory_sha256}},canary:{host_ipv4_tcp:"ready",host_ipv6_tcp:"ready",host_ipv4_dns_udp:"ready",host_ipv4_dns_tcp:"ready",host_ipv6_dns_udp:"ready",host_ipv6_dns_tcp:"ready",guest_ipv4_tcp:"blocked",guest_ipv4_dns_udp:"blocked",guest_ipv4_dns_tcp:"blocked",guest_ipv6_tcp:"blocked",guest_ipv6_dns_udp:"blocked",guest_ipv6_dns_tcp:"blocked",target_addresses:["10.0.2.2","2001:db8::1"]},checks:$checks}' \
    > "$receipt_tmp"
chmod 600 "$receipt_tmp"
jq -e . "$receipt_tmp" >/dev/null
receipt_augmented="$state_dir/barrier-receipt.json.augmented.$RANDOM"
jq --argjson managed_mainpid "$managed_mainpid" \
    '.guest += {managed_mainpid:$managed_mainpid,managed_dut_paths_absent:true,default_routes_absent:true,dns_upstreams_absent:true,ntp_disabled:true,ssh_forwarding_disabled:true} |
     .canary += {server_logged_host_dns_positive:true,server_received_guest_dns_query:false}' \
    "$receipt_tmp" > "$receipt_augmented"
chmod 600 "$receipt_augmented"
mv -- "$receipt_augmented" "$receipt_tmp"
receipt_path="$receipt_tmp" validate_receipt
mv -- "$receipt_tmp" "$receipt_path"
chmod 600 "$receipt_path"
if acceptance_output=$(bash "$script_dir/guest-barrier-check.sh" acceptance "$state_dir" 2>&1); then
    mv -T -- "$receipt_path" "$state_dir/barrier-receipt.rejected.$RANDOM.json"
    printf 'Acceptance unexpectedly passed before explicit independent-review authorization.\n' >&2
    exit 1
fi
[[ "$acceptance_output" == *'has not been explicitly authorized after independent review'* ]] || {
    mv -T -- "$receipt_path" "$state_dir/barrier-receipt.rejected.$RANDOM.json"
    printf 'Pre-authorization acceptance failed for an unexpected reason: %s\n' "$acceptance_output" >&2
    exit 1
}
printf '%s\n' "$acceptance_output" > "$state_dir/acceptance-before-authorization.log"
chmod 600 "$state_dir/acceptance-before-authorization.log"
receipt_tmp="$state_dir/barrier-receipt.json.tmp.$RANDOM"
jq '. + {authorization_gate:{pre_authorization_acceptance:"blocked"}}' "$receipt_path" > "$receipt_tmp"
chmod 600 "$receipt_tmp"
jq -e . "$receipt_tmp" >/dev/null
mv -- "$receipt_tmp" "$receipt_path"
chmod 600 "$receipt_path"
trap - EXIT INT TERM
cleanup_canaries
receipt_sha256=$(sha256sum "$receipt_path" | awk '{ print $1 }')
printf 'Fresh guest barrier receipt written: %s\n' "$receipt_path"
printf 'Receipt SHA-256: %s\n' "$receipt_sha256"
printf 'Acceptance was rejected before authorization; independent review is required before authorize.\n'
printf 'Only private/local canaries and reserved documentation addresses were used; this is not a public reachability test.\n'
printf 'After independent review approves this exact digest, authorize with: tests/Traefik.Acceptance/guest-barrier-check.sh authorize %q %s\n' "$state_dir" "$receipt_sha256"
