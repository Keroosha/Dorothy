# Docker container dependencies on host content directories

## Implementation

- `HostContentItem.Directory` exposes the typed `HostContentDirectory` identity for a declared `directory`.
- Docker bind mounts can use `DockerBuilders.hostDirectory item.Directory.Value`; `usesDirectory` declares a dependency without a mount (for example, a shared root directory).
- The Debian builder rejects any dependency not reference-identical to a directory in that host's `content` block. The Docker builder preserves existing container dependency ordering and adds only each container's declared host-directory resources to its Pulumi `DependsOn`.
- Containers also depend on declared firewalld policies whose egress includes `docker`. This ensures the Docker guard resource completes before container creation; it does not prove the host's actual packet path is blocked.
- No provider or helper changes: both dependencies are expressible entirely in the DSL/Pulumi graph.
- `HostContentTests` captures the actual container resource options and asserts its mounted and explicit parent directories plus the Docker firewalld guard are dependencies, while an unrelated directory is not. It also checks the emitted bind path/access and rejection of an undeclared directory. The fixture declares Docker before content to cover source-order independence.

## Verification

```text
dotnet test DSL/Dorothy.slnx --configuration Release --filter 'FullyQualifiedName~HostContentTests|FullyQualifiedName~FirewalldDeploymentTests|FullyQualifiedName~DockerJobDeploymentTests'
Passed: 21, Failed: 0, Skipped: 0.

dotnet test DSL/Dorothy.slnx --configuration Release --filter 'TestCategory!=Sandbox'
Passed: 381, Failed: 0, Skipped: 3.
```

The disposable Debian 13 first-apply/runtime-UID/replacement/network proof is not represented by these Pulumi graph tests and remains a separate integration requirement. No private MyIaC paths, hostnames, or infrastructure facts are included in this public specification.