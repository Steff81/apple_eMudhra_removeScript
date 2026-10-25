#!/bin/bash
#
# remove_emudhra_roots.sh
#
# Autor:   Steffen Edinger
# Quelle:  Apple Support HT149555 – https://support.apple.com/en-us/149555
#          (veröffentlicht 23.10.2026)
#
# Zweck:   Entfernt die Root-CAs "emSign ECC Root CA - G3" (und optional
#          "AAA Certificate Services") aus /etc/ssl/cert.pem. Hintergrund:
#          Schlüssel von acht eMudhra-Zwischen-CAs wurden kompromittiert.
#          Safari/Mail/Apple-Frameworks sind bereits durch Apple geschützt,
#          Kommandozeilenwerkzeuge (curl, git, python3, ruby, perl, openssl),
#          die /etc/ssl/cert.pem nutzen, jedoch noch nicht.
#
# Nutzung: ./remove_emudhra_roots.sh [Optionen]
#   --check        Nur prüfen (kein sudo, keine Änderung)
#   --with-aaa     Zusätzlich "AAA Certificate Services" entfernen
#                  (Achtung: auch legitime Zertifikate, die daran hängen,
#                  werden über cert.pem bis zum Apple-Update nicht mehr akzeptiert)
#   --restore      Backup /etc/ssl/cert.pem.orig zurückspielen
#   --file PFAD    Andere cert.pem verwenden (zum Testen)
#   -h, --help     Hilfe
#
# Hinweis: Nach einem macOS-Update kann cert.pem durch Apples Version ersetzt
#          werden. Dann Skript erneut ausführen (ggf. altes Backup löschen,
#          das Skript weist darauf hin).

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

# Betroffene Zwischenzertifikate (SHA-256, lt. Apple) – nur zur Prüfung, ob sie
# (unerwartet) noch direkt in cert.pem stehen.
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
fail() { printf '  [FEHLER] %s\n' "$*" >&2; }
info() { printf '%s\n' "$*"; }

usage() { sed -n '2,29p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [ $# -gt 0 ]; do
  case "$1" in
    --check)    MODE="check" ;;
    --restore)  MODE="restore" ;;
    --with-aaa) WITH_AAA=1 ;;
    --file)     shift; [ $# -gt 0 ] || { fail "--file braucht einen Pfad"; exit 2; }; CERT="$1" ;;
    -h|--help)  usage ;;
    *)          fail "Unbekannte Option: $1"; exit 2 ;;
  esac
  shift
done

BACKUP="${CERT}.orig"

# Was gilt als "noch enthalten"? Ohne --with-aaa zählt nur die emSign ECC Root CA - G3.
if [ "$WITH_AAA" -eq 1 ]; then ACTIVE="$PATTERN"; else ACTIVE='emSign ECC Root CA - G3'; fi

# sudo nur nötig, wenn wir nicht schon root sind
if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo"; fi

info "remove_emudhra_roots.sh – Autor: $AUTHOR"
info "Datei: $CERT"
info ""

if [ "$(uname -s)" != "Darwin" ] && [ "$CERT" = "/etc/ssl/cert.pem" ]; then
  warn "Dies ist kein macOS-System."
fi
[ -r "$CERT" ] || { fail "$CERT nicht lesbar/nicht vorhanden."; exit 1; }
command -v openssl >/dev/null 2>&1 || { fail "openssl nicht gefunden."; exit 1; }

# ---------------------------------------------------------------- Prüfungen --
count_certs() { grep -c '^-----BEGIN CERTIFICATE-----' "$1"; }

# Liste der Subjects aller Zertifikate (eine Zeile pro Zertifikat)
list_subjects() {
  openssl crl2pkcs7 -nocrl -certfile "$1" 2>/dev/null \
    | openssl pkcs7 -print_certs -noout 2>/dev/null
}

# Datei strukturell gültig? (BEGIN == END, openssl kann alles parsen)
validate_file() {
  local f="$1" b e p
  b=$(grep -c '^-----BEGIN CERTIFICATE-----' "$f")
  e=$(grep -c '^-----END CERTIFICATE-----' "$f")
  [ "$b" -gt 0 ] && [ "$b" -eq "$e" ] || return 1
  p=$(list_subjects "$f" | grep -c '^subject=')
  [ "$p" -eq "$b" ]
}

# Gibt verbleibende betroffene Roots aus (leer = sauber)
remaining() {
  list_subjects "$1" | grep -E "$ACTIVE" || true
}

# Prüft, ob einer der 12 gesperrten Zwischenzertifikat-Fingerprints in der Datei steckt
check_bad_fps() {
  local f="$1" found=0 tmp fp
  tmp=$(mktemp -d) || return 0
  awk -v d="$tmp" '/-----BEGIN CERTIFICATE-----/{n++; fn=sprintf("%s/c%04d.pem",d,n)} fn{print > fn} /-----END CERTIFICATE-----/{close(fn); fn=""}' "$f"
  for c in "$tmp"/c*.pem; do
    [ -e "$c" ] || continue
    fp=$(openssl x509 -in "$c" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//; s/://g' | tr 'a-f' 'A-F')
    if [ -n "$fp" ] && printf '%s' "$BAD_FPS" | grep -q "$fp"; then
      warn "Gesperrtes Zwischenzertifikat direkt in der Datei: $fp"; found=1
    fi
  done
  rm -rf "$tmp"
  return $found
}

report() {
  local f="$1" rem
  info "Status von $f:"
  if validate_file "$f"; then ok "Datei strukturell gültig ($(count_certs "$f") Zertifikate)"
  else fail "Datei ist NICHT gültig/vollständig parsebar"; return 2; fi
  rem=$(remaining "$f")
  if [ -z "$rem" ]; then
    ok "Keine der betroffenen Root-CAs enthalten"
  else
    echo "$rem" | sed 's/^/          enthalten: /'
    return 1
  fi
  check_bad_fps "$f" && ok "Keines der 12 gesperrten Zwischenzertifikate direkt enthalten"
  if [ "$WITH_AAA" -eq 0 ] && list_subjects "$f" | grep -q 'AAA Certificate Services'; then
    warn "AAA Certificate Services ist enthalten (optional, nur mit --with-aaa entfernen)"
  fi
  return 0
}

# ------------------------------------------------------------------ Restore --
if [ "$MODE" = "restore" ]; then
  [ -e "$BACKUP" ] || { fail "Kein Backup unter $BACKUP gefunden."; exit 1; }
  validate_file "$BACKUP" || { fail "Backup ist ungültig – Abbruch."; exit 1; }
  $SUDO install -m 0644 -o "${OWNER_GROUP%%:*}" -g "${OWNER_GROUP##*:}" "$BACKUP" "$CERT" \
    || { fail "Zurückspielen fehlgeschlagen."; exit 1; }
  ok "Backup zurückgespielt."
  report "$CERT"; exit 0
fi

# -------------------------------------------------------------------- Check --
if [ "$MODE" = "check" ]; then
  report "$CERT"; rc=$?
  info ""
  if [ $rc -eq 0 ]; then info "Ergebnis: sauber."; exit 0; fi
  info "Ergebnis: betroffene Root-CA(s) noch enthalten. Ohne --check ausführen, um sie zu entfernen."
  exit $rc
fi

# -------------------------------------------------------------------- Apply --
info "Vorher:"
report "$CERT"; pre=$?
[ $pre -eq 2 ] && exit 1
BEFORE=$(count_certs "$CERT")
info ""

if [ $pre -eq 0 ]; then
  info "Nichts zu tun – die zu entfernenden Root-CAs sind nicht (mehr) in der Datei."
  info "Es wurde nichts geändert und kein Backup angelegt. Ein Neustart ist nicht nötig."
  exit 0
fi

# 1) Backup (bestehendes bleibt erhalten)
if [ -e "$BACKUP" ]; then
  ok "Backup existiert bereits ($BACKUP) – bleibt unverändert."
  if [ $pre -ne 0 ] && [ -z "$(remaining "$BACKUP")" ]; then
    warn "Das Backup enthält die betroffenen CAs nicht (veraltet, z.B. nach macOS-Update?)."
    warn "Ggf. zuerst: sudo rm $BACKUP  und Skript erneut starten."
  fi
else
  $SUDO cp -p "$CERT" "$BACKUP" || { fail "Backup fehlgeschlagen."; exit 1; }
  ok "Backup erstellt: $BACKUP"
fi


strip_section() { # $1=Header $2=Eingabe $3=Ausgabe
  awk -v s="$1" '/^(===|###) /{skip=0} $0==s{skip=1} !skip' "$2" > "$3"
}

TMP1=$(mktemp) || exit 1
TMP2=$(mktemp) || exit 1
trap 'rm -f "$TMP1" "$TMP2"' EXIT

# 2) emSign ECC Root CA - G3 entfernen
strip_section "$ECC_HDR" "$CERT" "$TMP1"
cp "$TMP1" "$TMP2"
# 3) optional AAA Certificate Services
if [ "$WITH_AAA" -eq 1 ]; then
  strip_section "$AAA_HDR" "$TMP1" "$TMP2"
fi

# Plausibilitätsprüfung vor dem Überschreiben
[ -s "$TMP2" ] || { fail "Ergebnisdatei leer – Abbruch, nichts geändert."; exit 1; }
validate_file "$TMP2" || { fail "Ergebnisdatei ungültig – Abbruch, nichts geändert."; exit 1; }
AFTER=$(count_certs "$TMP2")
REMOVED=$((BEFORE - AFTER))
if [ "$REMOVED" -lt 0 ] || [ "$REMOVED" -gt 3 ]; then
  fail "Unerwartete Anzahl entfernter Zertifikate ($REMOVED) – Abbruch, nichts geändert."; exit 1
fi
if [ -n "$(remaining "$TMP2" | grep -E 'emSign ECC Root CA - G3')" ]; then
  fail "emSign ECC Root CA - G3 wäre noch enthalten (Header nicht gefunden?) – Abbruch."; exit 1
fi

$SUDO install -m 0644 -o "${OWNER_GROUP%%:*}" -g "${OWNER_GROUP##*:}" "$TMP2" "$CERT" \
  || { fail "Schreiben nach $CERT fehlgeschlagen (Backup bleibt unter $BACKUP)."; exit 1; }
ok "Entfernt: $REMOVED Zertifikat(e) ($BEFORE -> $AFTER)"
info ""

# 4) Nachprüfung
info "Nachher:"
report "$CERT"; rc=$?

# Funktionstest: TLS-Verbindung mit der bereinigten Datei
if [ "$CERT" = "/etc/ssl/cert.pem" ] && command -v curl >/dev/null 2>&1; then
  if curl -sS --max-time 10 -o /dev/null https://www.apple.com 2>/dev/null; then
    ok "Funktionstest: curl https://www.apple.com funktioniert"
  else
    warn "Funktionstest curl https://www.apple.com fehlgeschlagen (Netzwerk?) – bei Problemen: --restore"
  fi
fi

info ""
if [ "${rc:-0}" -ne 0 ]; then
  fail "Prüfung nicht bestanden. Zurückspielen: $0 --restore"; exit 1
fi
info "Fertig. Rückgängig: $0 --restore   |   Prüfen: $0 --check"
exit 0
