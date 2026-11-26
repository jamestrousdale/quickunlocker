# Maintain a deployment

## Relay and gateway updates

Keep the current Compose files, `.env`, `data/` and `letsencrypt/` before an
upgrade. The data directory contains public keys and PC names and MAC addresses.
The certificate state and `.env` contain credentials and need restricted
storage. Store the gateway TLS key separately on the trusted host.

Download the updated assets and verify checksums. Replace the relevant Compose
file and run `docker compose config --quiet` and `docker compose up -d` from its
directory. Use `-f docker-compose.gateway.yml` on the gateway and retain the
gateway environment and certificate mount. For source builds, add `--build`.
Check the service logs and test an unlock. A relay restart preserves the
disk-backed PC and key records. In-progress enrollments and unlock requests
expire when the relay process restarts.

For gateway certificate rotation, replace the contents of the mounted TLS
directory with the new files and restart the gateway so it reloads them. For a
rollback, redeploy the previous release's digest-pinned Compose files with the
same supported persistent state.

## Windows updates and password changes

Keep your fallback sign-in available. Verify the new EXE and DLL, keep them
beside each other, and run `register` from an elevated terminal to install the
new DLL. If Windows is still using the installed DLL, use your fallback sign-in
and close active lock-screen sessions before retrying the update. After changing
the Windows account password, update Quickunlocker's LSA secret with `password`.

```powershell
.\quickunlocker-setup.exe password
```

## Revoke or replace a phone

On every affected PC, list and revoke the credential.

```powershell
.\quickunlocker-setup.exe list
.\quickunlocker-setup.exe revoke CREDENTIAL_ID
```

Revocation removes the local Windows pin. The relay and phone may still display
that credential until their own records change. Remove the card from your
passkey manager if you intend to retire it there as well. Enroll the replacement
phone on the PCs you want it to unlock.

## Uninstall the Windows provider

Sign in using your normal password or PIN, then run from an elevated terminal.

```powershell
.\quickunlocker-setup.exe unregister
```

This removes the provider's registration and clears the Windows pins and
password secret. The copied DLL may remain under `%ProgramFiles%\Quickunlocker`.
After the provider is unloaded, you can remove the file. The relay's PC records
and the phone's passkeys are managed separately.
