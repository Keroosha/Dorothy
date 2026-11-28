# Sourced by cold-create.sh after the clean-host, cache and owner preconditions.
jpath=/etc/keroosha-iac/traefik/.keroosha-rollback.json
journal_sha(){ remote "sha256sum '$jpath' | cut -d' ' -f1"; }
interrupt(){
    local label=$1 point=$2
    control "receipt-$point-arm"
    if up > "$log/$label-$point-up.log" 2>&1; then echo 'expected receipt-commit interruption' >&2; return 1; fi
    control receipt-disarm > "$s/$label-$point.json"
}
no_create_id(){ p stack export --stack acceptance | jq -e --arg u "$urn" 'all(.deployment.resources[]; .urn!=$u or (.id//"")=="")' > "$log/$1-no-id"; }
identity(){ p stack export --stack acceptance | jq -e --arg u "$urn" --arg id "$owner" '[.deployment.resources[]|select(.urn==$u and .id==$id and .outputs.inSync==true)]|length==1'; }
positive(){
    local label=$1
    control commit-live > "$s/$label-before.txt"; stores > "$s/$label-before.stores"
    proof > "$log/$label-tls-before.log"
    up > "$log/$label-resume.log" 2>&1; identity
    remote "test ! -e '$jpath'"; proof > "$log/$label-tls-after.log"
    p refresh --yes --non-interactive > "$log/$label-refresh.log"; identity
    p preview --expect-no-changes --non-interactive > "$log/$label-preview.log"
    p up --skip-preview --yes --non-interactive --expect-no-changes > "$log/$label-idempotent.log"
    control commit-live > "$s/$label-after.txt"; cmp "$s/$label-before.txt" "$s/$label-after.txt"
    stores > "$s/$label-after.stores"; cmp "$s/$label-before.stores" "$s/$label-after.stores"
}
for label in cold stopped; do
    if [[ $label == stopped ]]; then remote 'systemctl stop keroosha-traefik.service'; export TRAEFIK_ACCEPTANCE_LOG_LEVEL=INFO; fi
    interrupt "$label" before
    parent=$(journal_sha); [[ $label != cold ]] || no_create_id "$label-before"
    interrupt "$label" after
    [[ $parent == "$(journal_sha)" ]]; [[ $label != cold ]] || no_create_id "$label-after"
    jq -nes --slurpfile a "$s/$label-before.json" --slurpfile b "$s/$label-after.json" '$a[0].generation==$b[0].generation and $a[0].invocation==$b[0].invocation and $a[0].parent==$b[0].parent and $a[0].next==$b[0].next' >/dev/null
    positive "$label"
    if [[ $label == cold ]]; then remote "cp -p /etc/keroosha-iac/traefik/.keroosha-static-receipt '$GUEST_ROOT/old-confirmation'"; fi
done
# New transaction, new process: the static receipt on disk still describes the old one.
remote 'systemctl stop keroosha-traefik.service'; export TRAEFIK_ACCEPTANCE_LOG_LEVEL=DEBUG
interrupt external after
parent=$(journal_sha); original=$(jq -er .invocation "$s/external-after.json")
if TRAEFIK_ACCEPTANCE_PHASE=withdraw-udp up > "$log/unbound-request.log" 2>&1; then exit 1; fi
grep -Fq 'different declaration cannot finish pending receipt commit' "$log/unbound-request.log"
control receipt-tamper
control commit-live > "$s/foreign-before.txt"
if up > "$log/receipt-refusal.log" 2>&1; then exit 1; fi
grep -Fq 'receipt is neither the previous confirmation nor this transaction' "$log/receipt-refusal.log"
control commit-live > "$s/foreign-after.txt"; cmp "$s/foreign-before.txt" "$s/foreign-after.txt"; [[ $parent == "$(journal_sha)" ]]
control receipt-reconcile > /dev/null
remote 'systemctl restart keroosha-traefik.service'; independent=$(remote 'systemctl show keroosha-traefik.service -p InvocationID --value'); [[ $independent != "$original" ]]
control commit-live > "$s/external-before.txt"
if up > "$log/external-commit-refusal.log" 2>&1; then exit 1; fi
grep -Fq 'receipt commit invocation changed' "$log/external-commit-refusal.log"
control commit-live > "$s/external-after.txt"; cmp "$s/external-before.txt" "$s/external-after.txt"; [[ $parent == "$(journal_sha)" ]]; proof > "$log/external-retained-tls.log"
handoff install
if handoff retire > "$log/external-active-handoff-refusal.log" 2>&1; then exit 1; fi
handoff stop; handoff negatives; handoff interrupt; handoff retire
p up --refresh --yes --non-interactive --parallel 1 > "$log/external-operator-up.log"; identity; proof > "$log/external-operator-tls.log"
stores > "$s/terminal-before-delete.stores"; cmp "$s/cold-before.stores" "$s/terminal-before-delete.stores"
TRAEFIK_ACCEPTANCE_PHASE=delete up > "$log/terminal-delete.log"; stores > "$s/terminal-after-delete.stores"; cmp "$s/terminal-before-delete.stores" "$s/terminal-after-delete.stores"
remote "test ! -e '$jpath' && test ! -e /etc/keroosha-iac/traefik/static.yml && test ! -e /usr/local/libexec/keroosha-iac/traefik"
