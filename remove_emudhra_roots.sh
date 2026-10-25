#!/bin/bash
#
# remove_emudhra_roots.sh
#
# Author:  Steffen Edinger
# Source:  Apple Support article 149555 – https://support.apple.com/en-us/149555
#          (published 23 Oct 2026)
#
# Purpose: Removes the root CAs "emSign ECC Root CA - G3" (and optionally
#          "AAA Certificate Services") from /etc/ssl/cert.pem. Background:
#          the keys of eight eMudhra intermediate CAs were compromised.
#          Safari/Mail/Apple frameworks are already protected by Apple, but
#          command-line tools (curl, git, python3, ruby, perl, openssl) that
#          use /etc/ssl/cert.pem are not yet.
#
# Usage:   ./remove_emudhra_roots.sh [options]
#   --check        Verify only (no sudo, no changes)
#   --with-aaa     Additionally remove "AAA Certificate Services"
#                  (Caution: legitimate certificates chaining to it will also
#                  no longer be accepted via cert.pem until Apple's update)
#   --restore      Restore backup /etc/ssl/cert.pem.orig
#   --file PATH    Use a different cert.pem (for testing)
#   -h, --help     Show help
#
# Note:    A macOS update may replace cert.pem with Apple's version. Run the
#          script again then (delete the old backup if the script tells you to).

set -u
set -o pipefail

AUTHOR="Steffen Edinger"
CERT="/etc/ssl/cert.pem"
MODE="apply"
WITH_AAA=0
OWNER_GROUP="${OWNER_GROUP:-root:wheel}"

ECC_HDR='=== /C=IN/OU=emSign PKI/O=eMudhra Technologies Limited/CN=emSign ECC Root CA - G3'
AAA_HDR='=== /C=GB/ST=Greater Manchester/L=Salford/O=Comodo CA Limited/CN=AAA Certificate Services'
PATTERN='emSign ECC Root CA - G3|AAA Certificate Services'

# Affected intermediate certificates (SHA-256, per Apple) – only used to check
# whether they are (unexpectedly) present directly in cert.pem.
BAD_FPS="
E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838
98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B
42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493
432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3
CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F
0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19
579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512
5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699
45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE
FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F
7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489
62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72
"

ok()   { printf '  [OK]    %s\n' "$*"; }
warn() { printf '  [WARN]  %s\n' "$*"; }
fail() { printf '  [ERROR] %s\n' "$*" >&2; }
info() { printf '%s\n' "$*"; }

usage() { sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [ $# -gt 0 ]; do
  case "$1" in
    --check)    MODE="check" ;;
    --restore)  MODE="restore" ;;
    --with-aaa) WITH_AAA=1 ;;
    --file)     shift; [ $# -gt 0 ] || { fail "--file requires a path"; exit 2; }; CERT="$1" ;;
    -h|--help)  usage ;;
    *)          fail "Unknown option: $1"; exit 2 ;;
  esac
  shift
done

BACKUP="${CERT}.orig"

# What counts as "still present"? Without --with-aaa only emSign ECC Root CA - G3 does.
if [ "$WITH_AAA" -eq 1 ]; then ACTIVE="$PATTERN"; else ACTIVE='emSign ECC Root CA - G3'; fi

# sudo is only needed if we are not root already
if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo"; fi

info "remove_emudhra_roots.sh – Author: $AUTHOR"
info "File: $CERT"
info ""

if [ "$(uname -s)" != "Darwin" ] && [ "$CERT" = "/etc/ssl/cert.pem" ]; then
  warn "This is not a macOS system."
fi
[ -r "$CERT" ] || { fail "$CERT is not readable or does not exist."; exit 1; }
command -v openssl >/dev/null 2>&1 || { fail "openssl not found."; exit 1; }

# ------------------------------------------------------------------- Checks --
count_certs() { grep -c '^-----BEGIN CERTIFICATE-----' "$1"; }

# Subjects of all certificates (one line per certificate)
list_subjects() {
  openssl crl2pkcs7 -nocrl -certfile "$1" 2>/dev/null \
    | openssl pkcs7 -print_certs -noout 2>/dev/null
}

# Is the file structurally valid? (BEGIN == END, openssl can parse everything)
validate_file() {
  local f="$1" b e p
  b=$(grep -c '^-----BEGIN CERTIFICATE-----' "$f")
  e=$(grep -c '^-----END CERTIFICATE-----' "$f")
  [ "$b" -gt 0 ] && [ "$b" -eq "$e" ] || return 1
  p=$(list_subjects "$f" | grep -c '^subject=')
  [ "$p" -eq "$b" ]
}

# Prints remaining affected roots (empty = clean)
remaining() {
  list_subjects "$1" | grep -E "$ACTIVE" || true
}

# Checks whether any of the 12 blocked intermediate fingerprints is in the file
check_bad_fps() {
  local f="$1" found=0 tmp fp
  tmp=$(mktemp -d) || return 0
  awk -v d="$tmp" '/-----BEGIN CERTIFICATE-----/{n++; fn=sprintf("%s/c%04d.pem",d,n)} fn{print > fn} /-----END CERTIFICATE-----/{close(fn); fn=""}' "$f"
  for c in "$tmp"/c*.pem; do
    [ -e "$c" ] || continue
    fp=$(openssl x509 -in "$c" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//; s/://g' | tr 'a-f' 'A-F')
    if [ -n "$fp" ] && printf '%s' "$BAD_FPS" | grep -q "$fp"; then
      warn "Blocked intermediate certificate found directly in the file: $fp"; found=1
    fi
  done
  rm -rf "$tmp"
  return $found
}

report() {
  local f="$1" rem
  info "Status of $f:"
  if validate_file "$f"; then ok "File is structurally valid ($(count_certs "$f") certificates)"
  else fail "File is NOT valid / cannot be fully parsed"; return 2; fi
  rem=$(remaining "$f")
  if [ -z "$rem" ]; then
    ok "None of the affected root CAs are present"
  else
    echo "$rem" | sed 's/^/          present: /'
    return 1
  fi
  check_bad_fps "$f" && ok "None of the 12 blocked intermediate certificates are present directly"
  if [ "$WITH_AAA" -eq 0 ] && list_subjects "$f" | grep -q 'AAA Certificate Services'; then
    warn "AAA Certificate Services is present (optional, only removed with --with-aaa)"
  fi
  return 0
}

# ------------------------------------------------------------------ Restore --
if [ "$MODE" = "restore" ]; then
  [ -e "$BACKUP" ] || { fail "No backup found at $BACKUP."; exit 1; }
  validate_file "$BACKUP" || { fail "Backup is invalid – aborting."; exit 1; }
  $SUDO install -m 0644 -o "${OWNER_GROUP%%:*}" -g "${OWNER_GROUP##*:}" "$BACKUP" "$CERT" \
    || { fail "Restore failed."; exit 1; }
  ok "Backup restored."
  report "$CERT"; exit 0
fi

# -------------------------------------------------------------------- Check --
if [ "$MODE" = "check" ]; then
  report "$CERT"; rc=$?
  info ""
  if [ $rc -eq 0 ]; then info "Result: clean."; exit 0; fi
  info "Result: affected root CA(s) still present. Run without --check to remove them."
  exit $rc
fi

# -------------------------------------------------------------------- Apply --
info "Before:"
report "$CERT"; pre=$?
[ $pre -eq 2 ] && exit 1
BEFORE=$(count_certs "$CERT")
info ""

if [ $pre -eq 0 ]; then
  info "Nothing to do – the root CAs to remove are not (or no longer) in the file."
  info "Nothing was changed and no backup was created. A restart is not required."
  exit 0
fi

# 1) Backup (an existing one is kept)
if [ -e "$BACKUP" ]; then
  ok "Backup already exists ($BACKUP) – left unchanged."
  if [ $pre -ne 0 ] && [ -z "$(remaining "$BACKUP")" ]; then
    warn "The backup does not contain the affected CAs (outdated, e.g. after a macOS update?)."
    warn "If needed, run 'sudo rm $BACKUP' first and start the script again."
  fi
else
  $SUDO cp -p "$CERT" "$BACKUP" || { fail "Backup failed."; exit 1; }
  ok "Backup created: $BACKUP"
fi


strip_section() { # $1=header $2=input $3=output
  awk -v s="$1" '/^(===|###) /{skip=0} $0==s{skip=1} !skip' "$2" > "$3"
}

TMP1=$(mktemp) || exit 1
TMP2=$(mktemp) || exit 1
trap 'rm -f "$TMP1" "$TMP2"' EXIT

# 2) Remove emSign ECC Root CA - G3
strip_section "$ECC_HDR" "$CERT" "$TMP1"
cp "$TMP1" "$TMP2"
# 3) Optionally remove AAA Certificate Services
if [ "$WITH_AAA" -eq 1 ]; then
  strip_section "$AAA_HDR" "$TMP1" "$TMP2"
fi

# Sanity checks before overwriting
[ -s "$TMP2" ] || { fail "Result file is empty – aborting, nothing changed."; exit 1; }
validate_file "$TMP2" || { fail "Result file is invalid – aborting, nothing changed."; exit 1; }
AFTER=$(count_certs "$TMP2")
REMOVED=$((BEFORE - AFTER))
if [ "$REMOVED" -lt 0 ] || [ "$REMOVED" -gt 3 ]; then
  fail "Unexpected number of removed certificates ($REMOVED) – aborting, nothing changed."; exit 1
fi
if [ -n "$(remaining "$TMP2" | grep -E 'emSign ECC Root CA - G3')" ]; then
  fail "emSign ECC Root CA - G3 would still be present (header not found?) – aborting."; exit 1
fi

$SUDO install -m 0644 -o "${OWNER_GROUP%%:*}" -g "${OWNER_GROUP##*:}" "$TMP2" "$CERT" \
  || { fail "Writing to $CERT failed (backup remains at $BACKUP)."; exit 1; }
ok "Removed: $REMOVED certificate(s) ($BEFORE -> $AFTER)"
info ""

# 4) Verification
info "After:"
report "$CERT"; rc=$?

# Functional test: TLS connection using the cleaned file
if [ "$CERT" = "/etc/ssl/cert.pem" ] && command -v curl >/dev/null 2>&1; then
  if curl -sS --max-time 10 -o /dev/null https://www.apple.com 2>/dev/null; then
    ok "Functional test: curl https://www.apple.com works"
  else
    warn "Functional test curl https://www.apple.com failed (network?) – if problems persist: --restore"
  fi
fi

info ""
if [ "${rc:-0}" -ne 0 ]; then
  fail "Verification failed. Restore with: $0 --restore"; exit 1
fi
info "Done. Undo: $0 --restore   |   Verify: $0 --check"
exit 0
