# Troubleshooting

## Safari or Windows cannot reach the origin

Check that the device resolves the configured hostname to the correct LAN IP.
Check the port and use HTTPS with a certificate valid for that hostname. For a
Pi deployment, inspect Traefik and relay logs.

```sh
docker compose logs --tail=100 traefik unlock
docker compose ps
```

For certificate issuance, verify the Cloudflare token scope, zone, DNS-01
configuration and ACME email. For a 403 from Traefik, check its `LAN_CIDR`
against the client's address. With the gateway, check that the Pi permits the
gateway's address and that the gateway can reach the Pi backend over HTTPS. A
gateway 502 indicates that it could not obtain an acceptable JSON response from
the relay. Check both services' logs and the backend hostname.

## Setup cannot enroll or the fingerprint differs

Check that the terminal is elevated, the password is the actual account
password, and an active wired adapter is present. Compare the origin you entered
with the phone URL, including any non-default port. Begin a fresh enrollment if
the link expired. If the fingerprint differs, cancel the session and verify the
origin and pairing setup before trying again.

## Wake succeeds but the PC stays asleep

Check BIOS or UEFI, adapter power settings, the recorded MAC address and wired
link. Try from sleep before testing shutdown. Confirm the relay can broadcast on
the PC's subnet and use the correct `WAKE_BROADCAST` if needed. Re-enroll after
replacing the wired adapter or moving the PC to a different broadcast network.

## No Unlock button appears

Confirm the Windows lock screen is showing, the provider is registered, and the
configured Windows SID has a pinned credential. Verify that the PC can resolve
and reach the same HTTPS origin as the phone. Refresh the phone app and allow
the provider time to post a new challenge.

## Passkey approval reaches Windows but sign-in fails

Check for a Windows **Sign in** confirmation. Try the built-in password or PIN.
If the Windows password changed, run the setup tool's `password` command while
signed in. If the relay hostname or account changed, check the current
configuration and enroll again.

For a persistent problem, leave the normal sign-in option available and use
`unregister` to remove Quickunlocker's provider. Restore a VM snapshot if you
are testing in a VM. Include the Windows build, deployment topology,
reproduction steps and redacted logs in a bug report. Enrollment and polling
URLs can contain temporary capabilities.
