# Apple / eMudhra – Root CA Removal for macOS

A shell script that removes the compromised eMudhra root CAs from `/etc/ssl/cert.pem` on macOS, including a backup, pre/post verification and a restore option.

**Author:** Steffen Edinger
**Source:** [Apple Support article 149555](https://support.apple.com/en-us/149555) (published 23 Oct 2026)

## Background

The keys of eight eMudhra intermediate certificate authorities were compromised. Six of them issue TLS certificates, which could be used to create certificates that appear valid for any website. eMudhra and Sectigo have revoked the affected certificates.

Apple has been blocking the 12 affected certificates automatically via configuration updates since 19 Oct 2026 (and the `emSign ECC Root CA - G3` since 23 Oct 2026). Safari, Mail and apps that use Apple's networking and security frameworks are protected by this.

**Not protected** are command-line tools that use `/etc/ssl/cert.pem` (`curl`, `git`, `python3`, `ruby`, `perl`, `openssl`) and apps that ship their own CA list. For the command-line tools, Apple describes how to remove the root CAs manually – this script automates exactly that.

> According to Apple, regular users do not need to take any action. This script is intended for administrators and developers who work in the Terminal.

## What the script does

1. Checks that `/etc/ssl/cert.pem` is valid and which affected root CAs it still contains.
2. Creates a backup at `/etc/ssl/cert.pem.orig` (an existing backup is never overwritten).
3. Removes `emSign ECC Root CA - G3`.
4. Optional (`--with-aaa`): also removes `AAA Certificate Services`.
5. Validates the result **before** overwriting the file (non-empty, parsable, plausible number of removed certificates). Otherwise it aborts without changing anything.
6. Verifies again afterwards, compares against the 12 blocked SHA-256 fingerprints and runs a functional test (`curl https://www.apple.com`).

If the root CA is not in the file (for example because Apple already removed it), the script reports "nothing to do" and neither changes the file nor creates a backup.

## Usage

```bash
chmod +x remove_emudhra_roots.sh

./remove_emudhra_roots.sh --check      # verify only, no sudo, no changes
./remove_emudhra_roots.sh              # remove emSign ECC Root CA - G3
./remove_emudhra_roots.sh --with-aaa   # additionally remove AAA Certificate Services
./remove_emudhra_roots.sh --restore    # restore the backup
```

| Option | Description |
|---|---|
| `--check` | Verification only. Exit code `0` = clean, `1` = affected root CA still present |
| `--with-aaa` | Additionally removes `AAA Certificate Services` |
| `--restore` | Restores `/etc/ssl/cert.pem.orig` |
| `--file PATH` | Use a different `cert.pem` (for testing) |
| `-h`, `--help` | Show help |

Writing to `/etc/ssl/cert.pem` requires `sudo`; the script invokes it itself. No restart of the Mac is needed – programs read the file again when they are restarted.

## Notes

- **Use `--with-aaa` with care:** afterwards, legitimate certificates that chain to `AAA Certificate Services` will also no longer be accepted via `cert.pem` until Apple corrects the file with an update. This affects every tool that uses this file. Without `--with-aaa`, AAA is only reported as an informational warning.
- **After macOS updates:** an update may replace `cert.pem` with Apple's version. Run `--check` and re-run the script if needed. If the backup is outdated, delete it with `sudo rm /etc/ssl/cert.pem.orig` and run the script again. Once Apple's software update is installed, this is no longer necessary for the standard tools and the Xcode Command Line Tools.
- **Undo:** `./remove_emudhra_roots.sh --restore`.
- **Testing:** the logic was tested against a synthetic `cert.pem` (check, remove, remove with AAA, restore). Run `--check` on your own Mac first before making changes.

## Affected intermediate certificates (SHA-256)

| Certificate | Issuer | SHA-256 |
|---|---|---|
| EM EV TLS CA - G3B | emSign Root TLS CA - G3 | `E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838` |
| EM OV TLS CA - G3B | emSign Root TLS CA - G3 | `98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B` |
| EM DV TLS CA - G3B | emSign Root TLS CA - G3 | `42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493` |
| EM EV TLS CA - G3C | emSign Root TLS CA - G3 | `432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3` |
| EM OV TLS CA - G3C | emSign Root TLS CA - G3 | `CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F` |
| EM DV TLS CA - G3C | emSign Root TLS CA - G3 | `0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19` |
| EM EV TLS CA - G3B | AAA Certificate Services | `579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512` |
| EM OV TLS CA - G3B | AAA Certificate Services | `5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699` |
| EM DV TLS CA - G3B | AAA Certificate Services | `45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE` |
| EM EV TLS CA - G3C | AAA Certificate Services | `FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F` |
| EM OV TLS CA - G3C | AAA Certificate Services | `7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489` |
| EM DV TLS CA - G3C | AAA Certificate Services | `62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72` |

## Disclaimer

This script modifies a system file. Use at your own risk; make sure you have a backup and run `--check` first.
