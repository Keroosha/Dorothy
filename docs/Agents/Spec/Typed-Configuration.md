# Typed configuration migration

## Scope

Replace stringly typed named SSH and Fail2Ban configuration helpers with domain values. Preserve complete native configuration support through explicit native/custom APIs. Use `System.TimeSpan` for elapsed durations, F# measures for sizes and CPU, and discriminated unions for sentinels, closed modes, and compound settings. Keep provider resource tokens, configuration/file-map schemas, and host lifecycle behavior unchanged.

## Implementation plan

1. Move shared `cpu` and `MiB` measures out of Docker into `Quantities.fs`; add `B` and `KiB` for native size contracts. Fix Docker `waitHealthy` validation against its integer-seconds destination, preserving documented ceiling for fractional waits.
2. Type the SSH named API, including timeout sentinels, channel timeouts, rekey limits, startup limits, source penalties and closed modes. Preserve ordered directives, Match/Include semantics, and explicit native escape hatches.
3. Type the Fail2Ban named API, including permanent bans, duration/size/count options, booleans and closed modes. Preserve native interpolation, formulas, commands, regexes and installation extensions through explicit native/custom values.
4. Migrate all in-repository callers and documentation without compatibility string overloads. Add behavioral boundary regressions, not catalogue/wiring assertions.
5. Run the integrated test suite and execute generated configuration through isolated native OpenSSH/Fail2Ban parsers. Exercise representative compound values, special values, interpolation and duration precision. Do not access or mutate production hosts or their Pulumi state.

## Compatibility

This is a source-breaking DSL change. Provider inputs remain native text; canonical duration spelling may therefore produce a textual Pulumi diff even when effective policy is unchanged. Downstream MyIaC must migrate before updating its Dorothy dependency. Production apply is outside this change.

## Verification

- `dotnet test Dorothy.slnx --configuration Release`: 199 passed, 1 skipped in the runner summary; no failures.
- Published the .NET provider for an isolated preview. No host-helper or provider lifecycle code changed.
- Executed a throwaway F# consumer against the built DSL and compiled both guide examples without deploying them.
- Debian container with OpenSSH 10.0p2 and Fail2Ban 1.1.0: generated SSH configurations passed `sshd -t`; `sshd -T` confirmed finite/disabled timeouts, channel patterns, 4 GiB rekey limits, default-data rekey intervals, startup limits, source penalties, forwarding mode and octal masks.
- Native Fail2Ban config validation and command-stream inspection confirmed finite/permanent bans, fractional findtime, native month interpolation, and database retention. A running isolated daemon reported bantime 604800 / -1 / 2629800, findtime 15.5, action timeout 0.25 and in-memory database retention 691200 seconds. Both disabled and in-memory database configurations started successfully.
- Exercised the Docker wait conversion at one tick, just over one second and `Int32.MaxValue` seconds; the public DSL rejected the previous 30,000-day overflow case.
- A separate disposable Pulumi project previewed six creates with the typed SSH/Fail2Ban API. SSH/SCP/SFTP were blocked and recorded zero attempted invocations. No apply or production preview was performed.
- Temporary consumers, preview backend/plugin installation and the native container were removed after verification. The implementation worktree is retained for review.
