#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# != 4 ]]; then
    printf 'Usage: write-evidence.sh /tmp/dorothy-traefik-acceptance.XXXXXXXX <candidate-provider-dir> <mode> <absolute-evidence-file-outside-state-dir>\n' >&2
    exit 2
fi
state_dir=$(realpath -e -- "$1")
provider_dir=$(realpath -e -- "$2")
mode=$3
destination=$4
case "$state_dir" in
    /tmp/dorothy-traefik-acceptance.*) ;;
    *) printf 'Refusing evidence input outside the private acceptance temp root.\n' >&2; exit 2 ;;
esac
[[ -d "$state_dir" && ! -L "$state_dir" \
   && -f "$state_dir/.owner" \
   && "$(<"$state_dir/.owner")" == dorothy-traefik-acceptance-owned-state-v1 ]] || {
    printf 'Private acceptance ownership marker is missing.\n' >&2
    exit 2
}
[[ "$mode" == full ]] || {
    printf 'Sanitized closure evidence is available only for a complete lifecycle run.\n' >&2
    exit 2
}
[[ -x "$provider_dir/pulumi-resource-keroosha" \
   && -x "$provider_dir/helper/linux-x64/keroosha-iac-helper" ]] || {
    printf 'Candidate provider artifacts are incomplete.\n' >&2
    exit 2
}
[[ "$destination" == /* ]] || { printf 'Evidence destination must be absolute.\n' >&2; exit 2; }
destination_parent=$(realpath -e -- "$(dirname -- "$destination")")
destination="$destination_parent/$(basename -- "$destination")"
case "$destination" in
    "$state_dir"|"$state_dir"/*) printf 'Evidence must be retained outside disposable private state.\n' >&2; exit 2 ;;
esac
[[ ! -e "$destination" && ! -L "$destination" ]] || {
    printf 'Refusing to overwrite existing sanitized acceptance evidence.\n' >&2
    exit 2
}

for command in git jq sha256sum sort find mktemp ln grep realpath stat; do
    command -v "$command" >/dev/null || { printf 'Missing required evidence command: %s\n' "$command" >&2; exit 2; }
done

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(realpath -e -- "$script_dir/../..")
candidate_source="$state_dir/candidate-source"
candidate_program="$state_dir/candidate-program"
candidate_helper="$provider_dir/helper/linux-x64/keroosha-iac-helper"
[[ -d "$candidate_source" && -d "$candidate_program" \
   && -f "$candidate_source/.owner" \
   && "$(<"$candidate_source/.owner")" == dorothy-traefik-candidate-source-v1 ]] || {
    printf 'Candidate source or published program evidence is missing.\n' >&2
    exit 2
}

source_tree_sha256() {
    (
        cd -- "$1"
        find . -type d \( -name obj -o -name bin \) -prune -o \
            -type f ! -name .owner -print0 \
            | LC_ALL=C sort -z \
            | while IFS= read -r -d '' path; do sha256sum -- "$path"; done
    ) | sha256sum | awk '{print $1}'
}
artifact_tree_sha256() {
    (
        cd -- "$1"
        find . -type f -print0 \
            | LC_ALL=C sort -z \
            | while IFS= read -r -d '' path; do sha256sum -- "$path"; done
    ) | sha256sum | awk '{print $1}'
}
file_sha256() { sha256sum -- "$1" | awk '{print $1}'; }
optional_sha256() {
    if [[ -f "$1" && ! -L "$1" ]]; then file_sha256 "$1"; else printf ''; fi
}

head_before=$(<"$state_dir/git-head-before.txt")
head_after=$(git -C "$repo_root" rev-parse HEAD)
[[ "$head_before" =~ ^[a-f0-9]{40,64}$ && "$head_after" =~ ^[a-f0-9]{40,64}$ ]] || {
    printf 'Git HEAD evidence is malformed.\n' >&2
    exit 1
}
[[ "$head_before" == "$head_after" ]] || { echo 'Refusing to attest a run spanning two source revisions.' >&2; exit 1; }
source_sha=$(source_tree_sha256 "$candidate_source")
program_sha=$(artifact_tree_sha256 "$candidate_program")
provider_sha=$(artifact_tree_sha256 "$provider_dir")
helper_sha=$(file_sha256 "$candidate_helper")
traefik_sha=$(optional_sha256 "$state_dir/guest-files/traefik")

for required in \
    "$state_dir/offline-preview.json" \
    "$state_dir/pagination-evidence.json" \
    "$state_dir/sni-seventeen.json" \
    "$state_dir/sni-drift-checkpoint.json" \
    "$state_dir/sni-repaired-checkpoint.json" \
    "$state_dir/after-review-suite-checkpoint.json" \
    "$state_dir/static-rollback-metrics.json" \
    "$state_dir/foreign-owner-delete-metrics.json" \
    "$state_dir/udp-withdrawal-metrics.json" \
    "$state_dir/transaction-review-metrics.json" \
    "$state_dir/review-suite-metrics.json" \
    "$state_dir/review-tls-metrics.json" \
    "$state_dir/barrier-receipt.json" \
    "$state_dir/barrier-authorization.json" \
    "$state_dir/secret-hygiene-metrics.json" \
    "$state_dir/post-reboot-journal-window.json" \
    "$state_dir/logs/guest-traefik-process-snapshot-full.log" \
    "$state_dir/ssh-argv-audit-full.counts" \
    "$state_dir/logs/review-client-checks.log" \
    "$state_dir/logs/review-client-identity-absent.log" \
    "$state_dir/logs/review-client-identity-wrong.log" \
    "$state_dir/logs/review-client-identity-accepted.log" \
    "$state_dir/logs/post-reboot-traefik-journal.log"; do
    [[ -s "$required" && ! -L "$required" ]] || {
        printf 'Required sanitized closure evidence is missing: %s\n' "${required##*/}" >&2
        exit 1
    }
done
for barrier_marker in "$state_dir/barrier-receipt.json" "$state_dir/barrier-authorization.json"; do
    [[ "$(stat -c %a "$barrier_marker")" == 600 ]] || {
        printf 'Guest barrier receipt/authorization marker permissions are not private.\n' >&2
        exit 1
    }
done

jq -e --slurpfile journalWindow "$state_dir/post-reboot-journal-window.json" '
    .pulumiConfigurationInputOutputCiphertextAsserted == true
    and .literalTsigValuesAbsentFromPulumiCheckpoints == true
    and .literalTsigValuesAbsentFromExposedHostArtifacts == true
    and .guestBarrierReceiptValidated == true
    and .guestBarrierAuthorizationValidated == true
    and .providerSshArgvComparedToEveryDnsFixtureToken == true
    and .providerSshArgvContainsNoDnsFixtureTokens == true
    and (.sshArgvAudit.invocations | type == "number" and . > 0 and floor == .)
    and (.sshArgvAudit.outgoingArgvEntriesChecked | type == "number" and . > 0 and floor == .)
    and (.sshArgvAudit.fixtureTokenChecks | type == "number" and . > 0 and floor == .)
    and (.sshArgvAudit.comparisons | type == "number" and . > 0 and floor == .)
    and (.guestTraefikMainPidCmdlineSnapshots | type == "number" and . > 0 and floor == .)
    and .literalTsigValuesAbsentFromTraefikMainPidCmdline == true
    and .literalTsigValuesAbsentFromTraefikConfigFilesUnitAndBoundedJournal == true
    and .postDelete.priorMainPidAbsent == true
    and .postDelete.serviceUnitRemoved == true
    and .postDelete.credentialEnvironmentRemoved == true
    and .rootOnlyRollbackSnapshotsMayContainReversibleCredentials == true
    and .postRebootJournalWindow.unit == $journalWindow[0].unit
    and .postRebootJournalWindow.since == $journalWindow[0].since
    and .postRebootJournalWindow.until == $journalWindow[0].until
    and .postRebootJournalWindow.maxLines == $journalWindow[0].maxLines
    and .postRebootJournalWindow.lines == $journalWindow[0].lineCount
    and (.postRebootJournalWindow.lines | type == "number" and . >= 0 and . <= 1000 and floor == .)
    and .rootOnlyRollbackSnapshotsArePrivateAndNotShared == true
' "$state_dir/secret-hygiene-metrics.json" >/dev/null || {
    printf 'Sanitized secret-hygiene metadata is incomplete or overclaims its scan scope.\n' >&2
    exit 1
}
jq -e '.unit == "keroosha-traefik.service" and (.since | type == "string" and length > 0) and (.until | type == "string" and length > 0) and .maxLines == 1000 and (.lineCount | type == "number" and . >= 0 and . <= 1000 and floor == .)' \
    "$state_dir/post-reboot-journal-window.json" >/dev/null || {
    printf 'Post-reboot journal window metadata is invalid or unbounded.\n' >&2
    exit 1
}

jq -e '.status == "unchanged" and .targetResourceCount == 1 and .sshInvocations == 0 and .refresh == false' \
    "$state_dir/offline-preview.json" >/dev/null || {
    printf 'Copied-checkpoint preview evidence is not a no-SSH unchanged result.\n' >&2
    exit 1
}

sni_drift=$(jq -c '
    [.deployment.resources[] | select(.type == "keroosha:debian:Traefik" and (.urn | endswith("::sandbox")))] as $resources
    | {inSync:$resources[0].outputs.inSync, tlsProbeSummary:$resources[0].outputs.tlsProbeSummary}
' "$state_dir/sni-drift-checkpoint.json")
sni_repaired=$(jq -c '
    [.deployment.resources[] | select(.type == "keroosha:debian:Traefik" and (.urn | endswith("::sandbox")))] as $resources
    | {inSync:$resources[0].outputs.inSync, tlsProbeSummary:$resources[0].outputs.tlsProbeSummary}
' "$state_dir/sni-repaired-checkpoint.json")
jq -e '.inSync == false and (.tlsProbeSummary | has("legacyProbesAttempted") and has("nativeProbesAttempted") and has("unprobedCount") and has("opaqueRouterCount") and has("truncated"))' \
    <<< "$sni_drift" >/dev/null || { printf 'SNI drift checkpoint lacks an observed false Read and TLS probe counts.\n' >&2; exit 1; }
jq -e '.inSync == true and (.tlsProbeSummary | has("legacyProbesAttempted") and has("nativeProbesAttempted") and has("unprobedCount") and has("opaqueRouterCount") and has("truncated"))' \
    <<< "$sni_repaired" >/dev/null || { printf 'SNI repair checkpoint lacks an observed true Read and TLS probe counts.\n' >&2; exit 1; }
seventeen_metrics=$(jq -c '
    def result:
        . as $stage
        | {
            inSync:$stage.inSync,
            summary:{
                legacyProbesAttempted:$stage.summary.legacyProbesAttempted,
                nativeProbesAttempted:$stage.summary.nativeProbesAttempted,
                opaqueRouterCount:$stage.summary.opaqueRouterCount,
                unprobedCount:$stage.summary.unprobedCount,
                truncated:$stage.summary.truncated
            },
            routerCount:(if ($stage.routers | type) == "array" or ($stage.routers | type) == "object" then ($stage.routers | length) else $stage.routers end),
            legacyOnly:$stage.legacyOnly
        };
    {
        candidateHealthy:(.candidateHealthy | result),
        candidateWithWrongLeaf:(.candidateWithWrongLeaf | result),
        candidateRepaired:(.candidateRepaired | result),
        seventeenNativeAndOneLegacy:(.seventeenNativeAndOneLegacy | result),
        frozenWithWrongLeaf:(if .frozenWithWrongLeaf == null then null else (.frozenWithWrongLeaf | result) end)
    }
' "$state_dir/sni-seventeen.json")
jq -e '
    .candidateHealthy.inSync == true
    and .candidateHealthy.legacyOnly == true
    and .candidateHealthy.summary.legacyProbesAttempted == 17
    and .candidateHealthy.summary.nativeProbesAttempted == 0
    and .candidateHealthy.summary.truncated == 0
    and .candidateWithWrongLeaf.inSync == false
    and .candidateWithWrongLeaf.legacyOnly == true
    and .candidateWithWrongLeaf.summary.legacyProbesAttempted == 17
    and .candidateWithWrongLeaf.summary.nativeProbesAttempted == 0
    and .candidateWithWrongLeaf.summary.truncated == 0
    and .candidateRepaired.inSync == true
    and .seventeenNativeAndOneLegacy.inSync == true
    and .seventeenNativeAndOneLegacy.legacyOnly == false
    and .seventeenNativeAndOneLegacy.summary.legacyProbesAttempted == 1
    and .seventeenNativeAndOneLegacy.summary.nativeProbesAttempted == 17
    and .seventeenNativeAndOneLegacy.summary.unprobedCount == 0
    and .seventeenNativeAndOneLegacy.summary.truncated == 0
' <<< "$seventeen_metrics" >/dev/null || {
    printf 'Legacy 17-target TLS evidence does not show complete probing and repair.\n' >&2
    exit 1
}

shopt -s nullglob
client_files=("$state_dir"/client-metrics-*.json)
transaction_files=(
    "$state_dir"/review-transactions-udp-before.json
    "$state_dir"/review-transactions-udp-after.json
    "$state_dir"/review-transactions-credential-staged.json
    "$state_dir"/review-transactions-credential-recovered.json
    "$state_dir"/review-transactions-static-staged.json
    "$state_dir"/review-transactions-static-recovered.json
    "$state_dir"/review-transactions-unverified-drift.json
    "$state_dir"/review-transactions-unverified-rollback.json
    "$state_dir"/review-transactions-unverified-repair.json
    "$state_dir"/review-transactions-binary-stage-injected.json
    "$state_dir"/review-transactions-binary-stage-clean.json
    "$state_dir"/review-transactions-unverified-drift.json
    "$state_dir"/review-transactions-unverified-rollback.json
    "$state_dir"/review-transactions-unverified-repair.json
    "$state_dir"/review-transactions-journal-v2.json
)
shopt -u nullglob
((${#client_files[@]} > 0)) || { printf 'No sanitized client metrics were retained.\n' >&2; exit 1; }
for transaction_file in "${transaction_files[@]}"; do
    [[ -s "$transaction_file" && ! -L "$transaction_file" ]] || {
        printf 'A sanitized transaction witness is missing: %s\n' "${transaction_file##*/}" >&2
        exit 1
    }
done
jq -e '.ownerDigestMatched == true' "$state_dir/review-transactions-binary-stage-injected.json" >/dev/null || {
    printf 'Binary staging fixture did not confirm matching ownership digests.\n' >&2
    exit 1
}
jq -e '.removed == true and .ownerDigestMatched == true' "$state_dir/review-transactions-binary-stage-clean.json" >/dev/null || {
    printf 'Binary staging cleanup did not report a removed matching-owner file.\n' >&2
    exit 1
}
client_metrics=$(jq -s 'sort_by(.runIndex)' "${client_files[@]}")
transaction_metrics=$(jq -n \
    --slurpfile udpBefore "$state_dir/review-transactions-udp-before.json" \
    --slurpfile udpAfter "$state_dir/review-transactions-udp-after.json" \
    --slurpfile credentialStaged "$state_dir/review-transactions-credential-staged.json" \
    --slurpfile credentialRecovered "$state_dir/review-transactions-credential-recovered.json" \
    --slurpfile staticStaged "$state_dir/review-transactions-static-staged.json" \
    --slurpfile staticRecovered "$state_dir/review-transactions-static-recovered.json" \
    --slurpfile binaryStageInjected "$state_dir/review-transactions-binary-stage-injected.json" \
    --slurpfile binaryStageClean "$state_dir/review-transactions-binary-stage-clean.json" \
    --slurpfile unverifiedDrift "$state_dir/review-transactions-unverified-drift.json" \
    --slurpfile unverifiedRollback "$state_dir/review-transactions-unverified-rollback.json" \
    --slurpfile unverifiedRepair "$state_dir/review-transactions-unverified-repair.json" \
    --slurpfile journalV2 "$state_dir/review-transactions-journal-v2.json" \
    '{
        udpLiveBefore:$udpBefore[0],
        udpWithdrawnAfter:$udpAfter[0],
        credentialStaged:$credentialStaged[0],
        credentialRecovered:$credentialRecovered[0],
        staticStaged:$staticStaged[0],
        staticRecovered:$staticRecovered[0],
        binaryStageInjected:$binaryStageInjected[0],
        binaryStageClean:$binaryStageClean[0],
        unverifiedDrift:$unverifiedDrift[0],
        unverifiedRollback:$unverifiedRollback[0],
        unverifiedRepair:$unverifiedRepair[0],
        journalV2Migration:$journalV2[0]
    }')
post_reboot_client=$(jq -c '[.[] | select(.mode == "after-reboot")] | sort_by(.runIndex) | .[0] // null' <<< "$client_metrics")
jq -e '.mode == "after-reboot" and .protocols.http2Version == "2" and .protocols.http3Version == "3" and .protocols.tcpProxyV2Verified == true and .protocols.tlsPassthroughVerified == true and .protocols.udpIngressProofs > 0 and .protocols.udpBackendProofs > 0 and .telemetry.resourceSpansRecords > 0 and .telemetry.resourceMetricsRecords > 0' \
    <<< "$post_reboot_client" >/dev/null || {
    printf 'Post-reboot client evidence is missing a real protocol or current telemetry result.\n' >&2
    exit 1
}
jq -e '.routeClientScenarioSuitePassed == true and .clientIdentityAccepted == true and .clientWithoutCertificateRejected == true and .independentlyIssuedClientCertificateRejected == true and .originalStructuredGraphRestored == true' \
    "$state_dir/review-suite-metrics.json" >/dev/null || {
    printf 'Reviewed route/client suite did not report all client-identity controls.\n' >&2
    exit 1
}
jq -e '.missingStoreReadInSync == false and .missingStoreUnprobedCount > 0 and .missingStoreRestoredReadInSync == true and .incompleteStoreReadInSync == false and .incompleteStoreUnprobedCount > 0 and .incompleteStoreRestoredReadInSync == true and .sameNameIssuerStorageSwitchVerified == true' \
    "$state_dir/review-tls-metrics.json" >/dev/null || {
    printf 'Reviewed ACME storage/issuer controls were incomplete.\n' >&2
    exit 1
}

journal_sha=$(file_sha256 "$state_dir/logs/post-reboot-traefik-journal.log")
journal_window=$(jq -c . "$state_dir/post-reboot-journal-window.json")
journal_lines=$(jq -er '.lineCount' "$state_dir/post-reboot-journal-window.json")
[[ "$journal_lines" == "$(wc -l < "$state_dir/logs/post-reboot-traefik-journal.log" | tr -d '[:space:]')" ]] || {
    printf 'Journal line count does not match the bounded window metadata.\n' >&2
    exit 1
}
trace_file=$(printf '%s\n' "$state_dir"/otel-after-reboot-evidence-*.txt | head -n 1)
[[ -s "$trace_file" ]] || { printf 'Post-reboot filtered trace evidence is missing.\n' >&2; exit 1; }
trace_sha=$(file_sha256 "$trace_file")

review_suite_sha=$(file_sha256 "$state_dir/logs/review-suite-runner.log")
review_client_checks_sha=$(file_sha256 "$state_dir/logs/review-client-checks.log")
review_identity_absent_sha=$(file_sha256 "$state_dir/logs/review-client-identity-absent.log")
review_identity_wrong_sha=$(file_sha256 "$state_dir/logs/review-client-identity-wrong.log")
review_identity_accepted_sha=$(file_sha256 "$state_dir/logs/review-client-identity-accepted.log")
review_tls_sha=$(file_sha256 "$state_dir/review-tls-metrics.json")
process_snapshot_sha=$(file_sha256 "$state_dir/logs/guest-traefik-process-snapshot-full.log")
ssh_argv_audit_sha=$(file_sha256 "$state_dir/ssh-argv-audit-full.counts")
barrier_receipt_sha=$(file_sha256 "$state_dir/barrier-receipt.json")
barrier_authorization_sha=$(file_sha256 "$state_dir/barrier-authorization.json")
artifact_digests=$(jq -n \
    --arg candidateSourceSha256 "$source_sha" \
    --arg candidateProgramTreeSha256 "$program_sha" \
    --arg candidateProviderTreeSha256 "$provider_sha" \
    --arg candidateHelperSha256 "$helper_sha" \
    --arg guestTraefikSha256 "$traefik_sha" \
    --arg postRebootJournalSha256 "$journal_sha" \
    --arg guestProcessSnapshotSha256 "$process_snapshot_sha" \
    --arg sshArgvAuditCountsSha256 "$ssh_argv_audit_sha" \
    --arg postRebootTraceEvidenceSha256 "$trace_sha" \
    --arg guestBarrierReceiptSha256 "$barrier_receipt_sha" \
    --arg guestBarrierAuthorizationSha256 "$barrier_authorization_sha" \
    --arg paginationEvidenceSha256 "$(file_sha256 "$state_dir/pagination-evidence.json")" \
    --arg legacyTlsSeventeenSha256 "$(file_sha256 "$state_dir/sni-seventeen.json")" \
    --arg reviewSuiteLogSha256 "$review_suite_sha" \
    --arg reviewClientChecksLogSha256 "$review_client_checks_sha" \
    --arg reviewClientIdentityAbsentLogSha256 "$review_identity_absent_sha" \
    --arg reviewClientIdentityWrongLogSha256 "$review_identity_wrong_sha" \
    --arg reviewClientIdentityAcceptedLogSha256 "$review_identity_accepted_sha" \
    --arg reviewTlsMetricsSha256 "$review_tls_sha" \
    '{
      candidateSourceTreeSha256:$candidateSourceSha256,
      candidateProgramTreeSha256:$candidateProgramTreeSha256,
      candidateProviderTreeSha256:$candidateProviderTreeSha256,
      candidateHelperSha256:$candidateHelperSha256,
      pinnedTraefikBinarySha256:(if $guestTraefikSha256 == "" then null else $guestTraefikSha256 end),
      postRebootJournalSha256:$postRebootJournalSha256,
      guestTraefikProcessSnapshotSha256:$guestProcessSnapshotSha256,
      providerSshArgvAuditCountsSha256:$sshArgvAuditCountsSha256,
      guestBarrierReceiptSha256:$guestBarrierReceiptSha256,
      guestBarrierAuthorizationSha256:$guestBarrierAuthorizationSha256,
      postRebootTraceEvidenceSha256:$postRebootTraceEvidenceSha256,
      paginationEvidenceSha256:$paginationEvidenceSha256,
      legacyTlsSeventeenEvidenceSha256:$legacyTlsSeventeenSha256,
      reviewSuiteLogSha256:$reviewSuiteLogSha256,
      reviewClientChecksLogSha256:$reviewClientChecksLogSha256,
      reviewClientIdentityAbsentLogSha256:$reviewClientIdentityAbsentLogSha256,
      reviewClientIdentityWrongLogSha256:$reviewClientIdentityWrongLogSha256,
      reviewClientIdentityAcceptedLogSha256:$reviewClientIdentityAcceptedLogSha256,
      reviewTlsMetricsSha256:$reviewTlsMetricsSha256
    }')

mkdir -m 700 -p "$destination_parent"
temporary=$(mktemp "$destination_parent/.$(basename -- "$destination").tmp.XXXXXXXX")
if ! jq -n \
    --arg mode "$mode" \
    --arg headBefore "$head_before" \
    --arg headAfter "$head_after" \
    --arg sourceSha "$source_sha" \
    --argjson offline "$(jq -c '{status,targetResourceCount,sshInvocations,refresh}' "$state_dir/offline-preview.json")" \
    --argjson paginationPassed true \
    --arg paginationSha "$(file_sha256 "$state_dir/pagination-evidence.json")" \
    --arg seventeenSha "$(file_sha256 "$state_dir/sni-seventeen.json")" \
    --argjson sniDrift "$sni_drift" \
    --argjson sniRepaired "$sni_repaired" \
    --argjson sniSeventeen "$seventeen_metrics" \
    --slurpfile reviewSuite "$state_dir/review-suite-metrics.json" \
    --slurpfile reviewTls "$state_dir/review-tls-metrics.json" \
    --argjson clients "$client_metrics" \
    --argjson postReboot "$post_reboot_client" \
    --argjson transactions "$transaction_metrics" \
    --slurpfile rollback "$state_dir/static-rollback-metrics.json" \
    --slurpfile foreignDelete "$state_dir/foreign-owner-delete-metrics.json" \
    --slurpfile udpWithdrawal "$state_dir/udp-withdrawal-metrics.json" \
    --slurpfile transactionSummary "$state_dir/transaction-review-metrics.json" \
    --slurpfile secretHygiene "$state_dir/secret-hygiene-metrics.json" \
    --argjson journalLines "$journal_lines" \
    --argjson journalWindow "$journal_window" \
    --argjson digests "$artifact_digests" \
    '{
        schema: 1,
        result: "passed",
        mode: $mode,
        git: {headBefore:$headBefore, headAfter:$headAfter},
        testedSourceSha256: $sourceSha,
        artifactDigests: $digests,
        stages: {
            copiedCheckpointPreview: {
                passed: ($offline.status == "unchanged" and $offline.targetResourceCount == 1 and $offline.sshInvocations == 0 and $offline.refresh == false),
                status: $offline.status,
                targetResourceCount: $offline.targetResourceCount,
                sshInvocations: $offline.sshInvocations,
                refresh: $offline.refresh
            },
            legacyPaginationReview: {passed:$paginationPassed, evidenceSha256:$paginationSha},
            legacyTlsSeventeenReview: {passed:true, evidenceSha256:$seventeenSha, observations:$sniSeventeen},
            sniDriftRead: {passed:($sniDrift.inSync == false), inSync:$sniDrift.inSync, tlsProbeSummary:$sniDrift.tlsProbeSummary},
            sniRepairRead: {passed:($sniRepaired.inSync == true), inSync:$sniRepaired.inSync, tlsProbeSummary:$sniRepaired.tlsProbeSummary},
            reviewRouteClientSuite: $reviewSuite[0],
            reviewTlsStorage: $reviewTls[0],
            clientChecks: $clients,
            udpWithdrawal: $udpWithdrawal[0],
            transactions: {summary:$transactionSummary[0], witnesses:$transactions},
            staticRollback: $rollback[0],
            foreignOwnerDelete: $foreignDelete[0],
            postReboot: {
                passed:true,
                protocols:$postReboot.protocols,
                telemetry:$postReboot.telemetry,
                activeInstanceJournalLines:$journalLines,
                journalWindow:$journalWindow
            },
            secretHygiene: $secretHygiene[0]
        }
    }' > "$temporary"; then
    rm -f -- "$temporary"
    printf 'Could not construct sanitized acceptance evidence.\n' >&2
    exit 1
fi
chmod 600 "$temporary"
secret_files=()
for secret_fixture in "$state_dir/dns-tsig-secret" "$state_dir"/dns-tsig-secret-*; do
    if [[ ! -e "$secret_fixture" && ! -L "$secret_fixture" ]]; then
        continue
    fi
    [[ -f "$secret_fixture" && ! -L "$secret_fixture" ]] || {
        rm -f -- "$temporary"
        printf 'A DNS credential fixture is not a regular private file.\n' >&2
        exit 1
    }
    secret_files+=("$(realpath -e -- "$secret_fixture")")
done
((${#secret_files[@]} > 0)) || {
    rm -f -- "$temporary"
    printf 'No owned DNS credential fixture was available for sanitized evidence checks.\n' >&2
    exit 1
}
for secret_fixture in "${secret_files[@]}"; do
    if grep -aFq -f "$secret_fixture" "$temporary"; then
        rm -f -- "$temporary"
        printf 'Sanitized acceptance evidence unexpectedly contains DNS TSIG plaintext.\n' >&2
        exit 1
    else
        grep_status=$?
        [[ "$grep_status" == 1 ]] || { rm -f -- "$temporary"; exit 1; }
    fi
done
if ! ln -- "$temporary" "$destination"; then
    rm -f -- "$temporary"
    printf 'Could not preserve sanitized acceptance evidence at the requested destination.\n' >&2
    exit 1
fi
rm -- "$temporary"
printf 'Wrote sanitized acceptance evidence: %s\n' "$destination"
