# Install the Windows components

Quickunlocker targets Windows x64. It needs a real account password and an
active wired Ethernet adapter during enrollment. Microsoft accounts in
passwordless mode cannot be used. Use a Windows VM snapshot for the first trial,
and make sure your regular password or PIN and a second administrator account
are available before registering the provider.

## Verify the files

Download `quickunlocker-setup.exe`, `quickunlocker.dll`, and `SHA256SUMS` from
the same
[GitHub release](https://github.com/jamestrousdale/quickunlocker/releases). Keep
the EXE and DLL in the same folder. Compare both hashes with the checksums
before running setup. Initial release binaries may be unsigned.

```powershell
Get-FileHash .\quickunlocker-setup.exe, .\quickunlocker.dll -Algorithm SHA256
Get-Content .\SHA256SUMS
```

## Configure, enroll, and register

Open an elevated Windows terminal. Run setup and enter the HTTPS origin your
phone will use, including the port if it differs from 443. For a local Windows
account, enter `.\username`. Other accounts use the domain and username accepted
by Windows. Enter the actual Windows password when prompted.

```powershell
.\quickunlocker-setup.exe configure
```

Setup checks the password with Windows and identifies the wired adapter it will
use for Wake-on-LAN. It displays a QR code and an enrollment URL.
[Finish enrollment on the phone](phone.md), then type the fingerprint shown on
the phone into the PC prompt.

After setup confirms that the passkey is pinned, register the provider.

```powershell
.\quickunlocker-setup.exe register
```

The command installs the DLL under `%ProgramFiles%\Quickunlocker` and adds the
provider registration. Windows keeps its built-in sign-in options available.
Test the phone option by locking Windows with **Win+L**. Then check that you can
still sign in with your usual password or PIN.

## Setup commands

| Command      | Effect                                                         |
| ------------ | -------------------------------------------------------------- |
| `configure`  | Set the origin and Windows account, then enroll a passkey.     |
| `register`   | Install and register the credential provider DLL.              |
| `enroll`     | Add a phone or reuse a passkey with the current configuration. |
| `list`       | List locally pinned credential IDs and fingerprints.           |
| `revoke ID`  | Remove a key from this PC's local pins.                        |
| `password`   | Validate and update the stored Windows password for this SID.  |
| `unregister` | Remove provider registration and erase local pins and secret.  |

Run all setup commands from an elevated terminal. If changing the origin or
Windows account, revoke the existing local pins and enroll again. See
[maintenance](../operate/maintenance.md) for updates and uninstallation.
