# Release and packaging process

Releez manages versioning and release PRs. The
[Start release workflow](https://github.com/jamestrousdale/quickunlocker/actions/workflows/start-release.yaml)
can preview a release before opening its release PR. Its dry-run option is
enabled by default. Review the version, notes and CI results before merging the
release PR into `master`.

Merging a release PR starts the
[Finalize release workflow](https://github.com/jamestrousdale/quickunlocker/actions/workflows/finalize-release.yaml).
The workflow builds and tests Windows x64 and native Linux arm64 and amd64
images. It publishes the Linux image index to GitHub Container Registry and
includes its digest in the release notes. The release Compose files reference
that immutable digest.

| Release asset                | Contents or purpose                 |
| ---------------------------- | ----------------------------------- |
| `quickunlocker.dll`          | Windows x64 credential provider.    |
| `quickunlocker-setup.exe`    | Elevated Windows x64 setup tool.    |
| `docker-compose.yml`         | Pi relay and Traefik deployment.    |
| `docker-compose.gateway.yml` | Independent gateway deployment.     |
| `.env.example`               | Pi relay environment template.      |
| `THIRD_PARTY_NOTICES.txt`    | Windows dependencies and notices.   |
| `SHA256SUMS`                 | SHA-256 hashes for the other files. |

The Windows workflow includes a signing placeholder. Treat the binaries as
unsigned unless the release states otherwise. Follow
[Windows installation](../install/windows.md) for checksum verification and
fallback sign-in, and [relay installation](../install/relay.md) for its
deployment.
