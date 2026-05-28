#!/usr/bin/env bash
#
# setup-signing-keys.sh — bootstrap Hanalyx's release signing keys.
#
# Generates a Hanalyx LLC master GPG key (certify-only, offline-grade) +
# a kensa signing subkey, then pushes the subkey to the GitHub repo as
# GPG_PRIVATE_KEY + GPG_PASSPHRASE. The master never enters the GitHub
# secret; only the subkey's private half does.
#
# Output artifacts (all under ~/hanalyx-key-backup/, chmod 0700):
#   MASTER-secret.asc      master + subkeys, offline backup. Move OFF
#                          this machine to your durable secrets vault.
#   REVOKE-master.asc      revocation certificate. Publish if the master
#                          is ever compromised. Move OFF this machine.
#   hanalyx-public.asc     public master + subkey. Safe to distribute.
#                          Operators import this with `rpm --import`.
#
# What lands in GitHub repo secrets:
#   GPG_PRIVATE_KEY    the SIGNING subkey only (master replaced with
#                      a gnu-dummy stub — verified before push)
#   GPG_PASSPHRASE     unlock for the subkey (same as master by default)
#
# After this script: move ~/hanalyx-key-backup/ to a durable vault and
# delete it from this machine. The script optionally removes the master
# private half from the daily keyring at the end (step 7).
#
# References:
#   docs/CONTRIBUTING.md      (release process)
#   .github/workflows/release.yml
#   .goreleaser.yaml          (where signature.key_file reads
#                              GPG_PRIVATE_KEY_PATH)

set -euo pipefail

# ---- config knobs --------------------------------------------------------

EMAIL_DEFAULT='ops@hanalyx.com'
REAL_NAME='Hanalyx LLC'
COMMENT='release signing'
MASTER_EXPIRY='2y'    # rotate or extend before this
SUBKEY_EXPIRY='2y'
BACKUP_DIR="$HOME/hanalyx-key-backup"
REPO='Hanalyx/kensa'

# ---- helpers -------------------------------------------------------------

red()    { printf '\033[31m%s\033[0m\n' "$*" >&2; }
green()  { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
bold()   { printf '\033[1m%s\033[0m\n' "$*"; }

confirm() {
  local prompt="${1:-Continue?}"
  read -rp "$prompt [y/N] " ans
  [[ "$ans" =~ ^[Yy]$ ]] || { red 'Aborted.'; exit 1; }
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 \
    || { red "missing prerequisite: $1"; exit 1; }
}

# ---- preflight -----------------------------------------------------------

bold '=== preflight ==='
for cmd in gpg gh awk sed shred chmod mkdir read; do
  require_cmd "$cmd"
done

# gh must be authenticated with admin on the repo.
if ! gh auth status >/dev/null 2>&1; then
  red 'gh CLI is not authenticated. Run: gh auth login'
  exit 1
fi
perm=$(gh api "repos/$REPO" --jq '.permissions.admin' 2>/dev/null || echo false)
if [[ "$perm" != true ]]; then
  red "you are not an admin on $REPO (gh reports permissions.admin=$perm)"
  exit 1
fi

EMAIL="${1:-$EMAIL_DEFAULT}"
yellow "Master UID will be: $REAL_NAME ($COMMENT) <$EMAIL>"
yellow "Master expiry: $MASTER_EXPIRY · subkey expiry: $SUBKEY_EXPIRY"
yellow "Backup dir: $BACKUP_DIR"
yellow "Target repo: $REPO"
echo
confirm 'Proceed?'

# Refuse to clobber an existing key with the same UID.
if gpg --list-secret-keys "$EMAIL" >/dev/null 2>&1; then
  red "a GPG secret key for $EMAIL already exists in your keyring."
  red 'Refusing to clobber. Either pass a different email as $1 or'
  red "delete the existing key first:  gpg --delete-secret-keys <FPR>"
  exit 1
fi

mkdir -p "$BACKUP_DIR"
chmod 0700 "$BACKUP_DIR"

# ---- 1. generate master (certify-only, RSA 4096) -------------------------

bold ''
bold '=== 1/7 generate master key (RSA 4096, certify-only) ==='
yellow "GPG will prompt you for a strong passphrase. WRITE IT DOWN —"
yellow "you'll record it in your durable secrets vault."

# Use gpg --batch --gen-key with a unattended-key-parm spec file. This
# is the canonical non-interactive recipe — no fragile prompt
# ordering, no "one extra prompt ate my UID" bug. The previous version
# of this script drove the interactive --full-generate-key flow via a
# stdin heredoc; an unexpected confirmation prompt in --expert mode
# shifted the input by one slot and captured "y" as the Real Name,
# requiring an after-the-fact UID rewrite. The batch form is immune
# because each field is named explicitly. (Pinentry still pops for
# the passphrase — the Passphrase: field is intentionally omitted so
# the user enters it interactively, never in plaintext.)
spec="$(mktemp -t kensa-gpg-spec.XXXXXX)"
chmod 0600 "$spec"
cat >"$spec" <<EOF
%echo Generating Hanalyx LLC master signing key
Key-Type: RSA
Key-Length: 4096
Key-Usage: cert
Name-Real: $REAL_NAME
Name-Comment: $COMMENT
Name-Email: $EMAIL
Expire-Date: $MASTER_EXPIRY
%ask-passphrase
%commit
%echo Master key generated
EOF
gpg --batch --gen-key "$spec"
shred -u "$spec"

MASTER_FPR=$(gpg --list-secret-keys --with-colons "$EMAIL" \
  | awk -F: '/^fpr:/ {print $10; exit}')
if [[ -z "$MASTER_FPR" ]]; then
  red 'failed to capture master fingerprint after generation'
  exit 1
fi
green "MASTER fingerprint: $MASTER_FPR"

# ---- 2. add the signing subkey -------------------------------------------

bold ''
bold '=== 2/7 add signing subkey for kensa releases ==='
gpg --quick-add-key "$MASTER_FPR" rsa4096 sign "$SUBKEY_EXPIRY"

SUBKEY_FPR=$(gpg --list-secret-keys --with-colons "$EMAIL" \
  | awk -F: '/^fpr:/ {print $10}' | sed -n '2p')
if [[ -z "$SUBKEY_FPR" ]]; then
  red 'failed to capture subkey fingerprint after add-key'
  exit 1
fi
green "SIGNING subkey fingerprint: $SUBKEY_FPR"

# ---- 3. revocation certificate -------------------------------------------

bold ''
bold '=== 3/7 generate revocation certificate ==='
yellow 'GPG will prompt: reason (0=no reason), description, then your passphrase.'
gpg --output "$BACKUP_DIR/REVOKE-master.asc" --gen-revoke "$MASTER_FPR"
chmod 0600 "$BACKUP_DIR/REVOKE-master.asc"
green "revocation cert: $BACKUP_DIR/REVOKE-master.asc"

# ---- 4. offline backup of master + public key ----------------------------

bold ''
bold '=== 4/7 export master backup + public key ==='
gpg --output "$BACKUP_DIR/MASTER-secret.asc" \
    --armor --export-secret-keys "$MASTER_FPR"
chmod 0600 "$BACKUP_DIR/MASTER-secret.asc"

gpg --output "$BACKUP_DIR/hanalyx-public.asc" \
    --armor --export "$MASTER_FPR"

green "master backup: $BACKUP_DIR/MASTER-secret.asc"
green "public key:    $BACKUP_DIR/hanalyx-public.asc"

# ---- 5. export ONLY the signing subkey + verify the master is stubbed ----

bold ''
bold '=== 5/7 export signing subkey for GitHub (master must be stubbed) ==='
SUBKEY_EXPORT="$(mktemp -t kensa-gpg-subkey.XXXXXX.asc)"
gpg --output "$SUBKEY_EXPORT" \
    --armor --export-secret-subkeys "${SUBKEY_FPR}!"
chmod 0600 "$SUBKEY_EXPORT"

# Critical safety: the export MUST replace the master private with a
# gnu-dummy stub. If it does not, we'd be about to push the master to
# GitHub. Bail loudly if not.
if gpg --list-packets "$SUBKEY_EXPORT" 2>&1 | grep -q 'gnu-dummy'; then
  green 'verified: master private replaced with gnu-dummy stub in the export'
else
  red 'SAFETY GATE FAILED — master private appears in the subkey export!'
  red "stopping before pushing to $REPO. Inspect: $SUBKEY_EXPORT"
  red 'Do NOT push this file anywhere. Shred it.'
  exit 1
fi

# ---- 6. push the secrets to GitHub ---------------------------------------

bold ''
bold "=== 6/7 push GPG_PRIVATE_KEY + GPG_PASSPHRASE to $REPO ==="
gh secret set GPG_PRIVATE_KEY --repo "$REPO" < "$SUBKEY_EXPORT"
green "GPG_PRIVATE_KEY set on $REPO"

yellow 'Enter the subkey passphrase (same as master by default) — silent prompt:'
read -rs phrase
echo
gh secret set GPG_PASSPHRASE --repo "$REPO" --body "$phrase"
unset phrase
green "GPG_PASSPHRASE set on $REPO"

shred -u "$SUBKEY_EXPORT"
green 'subkey export file shredded'

# ---- 7. (optional) remove master private from the daily keyring ----------

bold ''
bold '=== 7/7 (optional) remove master private half from this keyring ==='
yellow 'This keeps the signing subkey private (so you can still test-sign'
yellow 'locally) and the public master (so GPG knows the trust chain).'
yellow 'The master private is what leaves. Only do this AFTER you have'
yellow "moved $BACKUP_DIR/ to a durable vault (1Password / safe / USB)."
echo
yellow 'IMPORTANT: gpg --delete-secret-keys <master-fpr> deletes the ENTIRE'
yellow 'secret keyset (master AND subkeys). The correct subkey-preserving'
yellow 'pattern is: export the subkey alone, delete everything, then'
yellow 're-import just the subkey. That is what this script does.'
yellow '(An earlier version called --delete-secret-keys directly and'
yellow 'nuked the subkey too; bug found landing v0.2.0.)'
echo
read -rp 'Have you backed up the directory above? Type YES to confirm: ' ack
if [[ "$ack" == 'YES' ]]; then
  subkey_only="$(mktemp -t kensa-subkey-only.XXXXXX.asc)"
  chmod 0600 "$subkey_only"

  # 7a. Export the subkey alone — gnu-dummy stub for the master.
  gpg --output "$subkey_only" --armor --export-secret-subkeys "${SUBKEY_FPR}!"

  # 7b. Safety check: refuse to delete if the export is suspect.
  if ! gpg --list-packets "$subkey_only" 2>&1 | grep -q 'gnu-dummy'; then
    red 'SAFETY: subkey-only export does not contain a gnu-dummy stub'
    red "         for the master. Refusing to delete. Inspect: $subkey_only"
    shred -u "$subkey_only"
    exit 1
  fi

  # 7c. Delete the entire secret keyset (master AND subkey).
  gpg --batch --yes --delete-secret-keys "$MASTER_FPR"

  # 7d. Re-import just the subkey-only export.
  gpg --batch --import "$subkey_only"
  shred -u "$subkey_only"

  # 7e. Verify: master should be sec# (private absent), subkey should
  # still show ssb (private present).
  green 'master private removed; subkey private re-imported'
  echo
  yellow 'Expected: sec#  rsa4096 ... [C]   (# means private absent)'
  yellow '          ssb   rsa4096 ... [S]   (no # means private present)'
  echo
  gpg --list-secret-keys "$MASTER_FPR"
else
  yellow 'skipped — to run manually later, see step 7 in this script.'
fi

# ---- final verification --------------------------------------------------

bold ''
bold '=== final verification ==='
gh secret list --repo "$REPO"
echo
green 'All four secrets should now be present:'
green '  COSIGN_PASSWORD'
green '  COSIGN_PRIVATE_KEY'
green '  GPG_PASSPHRASE'
green '  GPG_PRIVATE_KEY'
echo
bold "Move $BACKUP_DIR/ to your durable vault now, then run:"
bold "  shred -u $BACKUP_DIR/MASTER-secret.asc $BACKUP_DIR/REVOKE-master.asc"
bold "  rm $BACKUP_DIR/hanalyx-public.asc   # (public, keep a copy somewhere distributable)"
echo
bold 'Ready to tag v0.2.0.'
