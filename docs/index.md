# Quickunlocker

Wake a wired Windows PC on your LAN and approve its sign-in with a passkey on
your iPhone. The Windows PC checks every approval against the key it pinned
during enrollment.

Quickunlocker has three parts.

- **Windows setup and credential provider.** The setup tool pins a passkey and
  registers an **Unlock with phone** sign-in option. The provider uses the
  computer's existing Windows account.
- **Pi relay.** The relay forwards passkey requests and responses and sends
  Wake-on-LAN packets on the local network.
- **Phone web app.** Open it in Safari or add it to your Home Screen. It can be
  served by the Pi or by an independent HTTPS gateway.

## Install and try it

1. [Set up the relay](install/relay.md) on a Linux Pi or another wired Linux
   host that can broadcast on the PC's LAN.
2. [Set up the trusted gateway](install/gateway.md) if the Pi is outside your
   trust boundary during phone enrollment.
3. [Install the Windows components](install/windows.md) and
   [enroll the phone](install/phone.md). For the first installation, use a
   Windows VM snapshot and confirm that your normal password or PIN works.
4. [Wake and unlock the PC](operate/wake-and-unlock.md) from the phone.

The documentation is hosted publicly. Your relay, phone app, and Windows sign-in
traffic stay on your LAN.

[Download release assets](https://github.com/jamestrousdale/quickunlocker/releases){
.md-button .md-button--primary }
[Read the security model](reference/security.md){ .md-button }
