# Wake and unlock

Open the phone app for your Quickunlocker origin. An enrolled PC appears as
**Wake** when it has no pending sign-in request. Tap **Wake** to send a
Wake-on-LAN packet. The app refreshes while visible and changes to **Unlock**
after Windows posts a challenge.

When the PC is already awake, lock it with **Win+L** and wait for **Unlock**.
Tap it and complete your phone's passkey verification. Approve requests you
started. Windows may display its own confirmation before completing sign-in.

If the request expires before you approve, keep the lock screen open and wait
for a fresh one. Use Windows password or PIN if the phone option is unavailable.

## Enable Wake-on-LAN

- Use wired Ethernet with the Pi and Windows PC on the same IPv4 broadcast
  network. Enrollment records the MAC address of a wired adapter.
- Enable Wake-on-LAN in BIOS or UEFI and enable **Wake on Magic Packet** in the
  Windows adapter settings. Enable **Allow this device to wake the computer**
  when the driver exposes it.
- Try waking from sleep first. Wake from shutdown depends on hardware, firmware
  and driver support. Disable Windows Fast Startup if your setup requires it for
  shutdown wake.
- If the Pi has several network interfaces, set `WAKE_BROADCAST` to the subnet
  broadcast address for the PC's network, such as `192.168.1.255` on
  `192.168.1.0/24`.

A successful Wake response means the relay sent the UDP packet. Check the PC's
progression to its lock screen to confirm that the device woke. Repeated Wake
requests are rate-limited. See the [troubleshooting guide](troubleshooting.md)
if the PC stays asleep.
