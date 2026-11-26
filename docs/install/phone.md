# Enroll a phone

Start from an elevated Windows setup session using `configure` on a new PC or
`enroll` on a configured PC. The code or link is valid for five minutes. The
link carries a short-lived capability, so share it only with the phone you
intend to enroll.

1. Scan the QR code in the Windows terminal with your iPhone or open the URL on
   the phone. The link should use the HTTPS origin you entered on the PC.
2. Choose **Create passkey**. Complete the phone's verification and save the
   passkey in the available passkey manager, such as iCloud Keychain or
   1Password.
3. Compare the phone fingerprint with the value shown by the PC. Type the
   phone's fingerprint at the PC prompt. If the values do not match, cancel the
   enrollment and start another session.
4. Open the root of the same HTTPS origin in Safari. To install it as a Home
   Screen app, use **Share → Add to Home Screen**.

The phone computes the fingerprint from the public key returned by the
authenticator. The setup tool recomputes it from the key it received before
pinning it. With a direct Pi deployment, trust the Pi's browser code during
pairing. Use the [independent gateway](gateway.md) when that trust is
unavailable.

## Reuse the passkey on another PC

Start enrollment on the second PC. Open its link using the same phone browser or
Home Screen app in which you originally created the passkey. Choose **Use
existing passkey**, verify on the phone, and confirm the fingerprint on the new
PC. Each PC stores its own pin and can revoke it independently.

The reuse option depends on the fingerprint kept in the original app's browser
storage. If that storage was cleared or Safari and the Home Screen app use
separate storage, create a new passkey from the enrollment page.
