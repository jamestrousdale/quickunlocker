# Build and test Quickunlocker

Run development commands from the repository root unless stated otherwise. The
[CI workflow](https://github.com/jamestrousdale/quickunlocker/actions/workflows/ci-checks.yaml)
covers Python checks, Windows builds and CTest, Mustard coverage reports, and
Linux container builds on arm64 and amd64. Automated checks exercise the
protocol and test binaries. The Windows secure desktop and physical wake require
separate acceptance testing.

## Python relay and gateway

Install the pinned tools through mise and sync the Python environment.

```sh
mise install
mise run python:uv-sync
mise run ci-checks
```

Run only the Python integration suite or generate its Cobertura report.

```sh
uv run --locked pytest -q
mise run python:check:coverage
uv run --locked coverage xml -o coverage-python.xml
```

The suite uses a software P-256 authenticator. It exercises registration, reuse,
expiry, long polling, Wake-on-LAN packet construction and rate limits, and the
verifier's rejection of forged or stale responses. Gateway tests exercise the
same workflow through the JSON proxy and check its response filtering. The relay
integration suite binds a loopback socket for one test.

## Windows build and tests

Use Windows x64 with Visual Studio C++ tools, the Windows SDK and CMake. The
CMake build downloads checksum-verified copies of nlohmann/json and the Nayuki
QR encoder.

```powershell
cmake -S windows -B windows/build -A x64
cmake --build windows/build --config Release
ctest --test-dir windows/build -C Release --output-on-failure --no-tests=error
```

| CTest target          | Scope                                                                                                                        |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `webauthn`            | Fixed valid and invalid assertions against the Windows verifier.                                                             |
| `credential_provider` | Loads the DLL, checks COM object lifetime and verifies that no tile appears without an advised session and matching account. |
| `setup_enrollment`    | Checks enrollment origin, fingerprint comparison and rejection of pin substitution.                                          |

For Windows coverage, install Ninja and LLVM x64 22 or newer alongside the
Visual Studio C++ toolchain. The CI job uses LLVM 22.1.8. With LLVM installed
under `%ProgramFiles%\LLVM`, run this command from PowerShell:

```powershell
./windows/collect-coverage.ps1
```

To use another LLVM installation, pass its root directory with
`-LlvmRoot 'C:\Tools\LLVM'`.

The script runs CTest in a separate clang-cl coverage build, merges its profiles
and writes `windows/build/coverage/coverage-cpp.lcov`. Mustard uploads Windows
coverage as its own report. Windows patch coverage is informational, and CI
requires a coverage upload from a successful Windows job. Python has a 100%
changed-line coverage gate. The README badges come from successful CI runs on
the default branch.

## Test against a running relay

Use the simulator to confirm that the browser and Pi can enroll and approve
before modifying Windows sign-in.

```sh
uv run --locked python pc-sim/unlock_client.py --relay https://unlock.home.example.com \
  enroll --pc-name lab-pc --mac 02:00:00:00:00:01
uv run --locked python pc-sim/unlock_client.py --relay https://unlock.home.example.com \
  unlock --pc-name lab-pc
```

Use an appropriate wired MAC for the PC you want to wake. Open the enrollment
link on the phone to pin the key. Approve the simulator's unlock in the phone
app and look for `VERIFIED` in the terminal. Set `PIN_FILE` to a temporary path
if you want to isolate a test from your normal simulator pins.

## Verify the deployment on Windows and the LAN

Use a Windows x64 VM snapshot for credential-provider testing. Enrollment
requires an adapter the guest reports as active wired hardware. Use a supported
physical Windows PC if the VM cannot supply one.

1. Confirm built-in sign-in and a second administrator account. Configure,
   enroll and register the provider.
2. Lock the PC, approve from the phone, and confirm sign-in. Repeat from a fresh
   Windows logon screen. Verify the fallback password and PIN.
3. Let a challenge expire, then approve a fresh one. Stop and restart the relay
   during a poll and verify that fallback sign-in still works.
4. Check passkey reuse across PCs, revocation, password changes and
   uninstallation. Verify the provider and secret are removed after running
   `unregister`.
5. Verify Wake from sleep against a wired physical PC. Test shutdown wake if the
   hardware supports it. For the independent gateway, verify that the phone and
   PC use its HTTPS origin and that both certificate chains validate.

Record versions, the deployment topology, and observed results. Redact
enrollment and polling URLs from logs.
