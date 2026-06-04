#!/bin/sh
#
# postinst.sh — kensa binary package, run after files are extracted.
#
# Surfaces a friendly warning when the rules corpus isn't installed —
# the binary can't do anything useful until either the kensa-rules
# package is installed or the operator passes --rules-dir to a custom
# corpus. We deliberately do NOT fetch anything from the network here
# (Fedora packaging guidelines forbid it; Debian discourages it; both
# would break enterprise mirrors and bypass the GPG/cosign trust chain
# the release ships with). The Recommends: kensa-rules dependency in
# the package metadata is what actually wires the corpus install on a
# stock `dnf install kensa` or `apt install kensa`.
#
# Idempotent and silent on the happy path: if /usr/share/kensa/rules
# has any .yml file, we exit 0 without output. Only when the corpus is
# absent do we emit the warning, which is read by the package manager
# UI on RPM (dnf shows post-script output) and the apt frontend on
# DEB. Operators who declined Recommends or installed kensa alone get
# clear next-step commands.
#
# Trade-offs we accepted in the v0.2.1 review:
#
#   * False positive in same transaction (kensa installed before
#     kensa-rules): the warning fires, then kensa-rules is extracted
#     immediately after. Self-correcting and dnf's transaction summary
#     already shows the operator both packages are queued. Acceptable.
#
#   * RPM and DEB share this script. nfpm wires the same file into
#     both formats; the syntax stays POSIX /bin/sh.

set -eu

# --- Service-handler support: ensure the 'kensa' group exists --------
# The package ships /etc/sudoers.d/kensa-systemd-helper, which grants
# members of the 'kensa' group passwordless root execution of the
# systemd helper. We create that group here, EMPTY: a fresh install
# hands the privilege to NOBODY. An administrator opts a user in
# explicitly with `usermod -aG kensa <user>`. Creating the group empty
# keeps the privilege boundary opt-in — the shipped sudoers rule is
# inert until a human deliberately adds a member.
#
# Idempotent: re-running on upgrade is a no-op when the group already
# exists. Failure to create the group is a warning, not an install
# failure — the sudoers rule simply stays inert (sudo treats an unknown
# group as no match) until the operator creates the group by hand.
#
# GETENT_CMD / GROUPADD_CMD are override hooks for the packaging tests
# (see packaging/postinst_test.go) exactly like RULES_DIR below; nothing
# sets them on a real install, so the defaults apply.
GETENT_CMD="${GETENT_CMD:-getent}"
GROUPADD_CMD="${GROUPADD_CMD:-groupadd}"
if ! "$GETENT_CMD" group kensa >/dev/null 2>&1; then
    "$GROUPADD_CMD" --system kensa >/dev/null 2>&1 || \
        printf '%s\n' "kensa post-install: could not create the 'kensa' group; create it with 'groupadd --system kensa' before using the service handlers." >&2
fi

# RULES_DIR is the path the kensa-rules package installs to. Env-
# overridable so unit tests can inject mock paths (see
# packaging/postinst_test.go). On a real install nothing sets it and
# the default applies.
RULES_DIR="${RULES_DIR:-/usr/share/kensa/rules}"

# Use ls -A to honour hidden files and quote to handle paths with
# spaces (none in practice but safe by reflex). Redirect ls's own
# diagnostics so a missing directory doesn't error before we get to
# check it.
if [ -d "$RULES_DIR" ] && [ -n "$(ls -A "$RULES_DIR" 2>/dev/null)" ]; then
    exit 0
fi

cat >&2 <<EOF

WARNING from kensa post-install:

  The kensa rules corpus is not installed at $RULES_DIR. The kensa
  CLI will refuse to run scans until rules are available. Three ways
  to fix this:

    a) Install the rules package (preferred):
         dnf install kensa-rules         (RHEL/Fedora/Rocky/Alma)
         apt install kensa-rules         (Debian/Ubuntu)

    b) Place your own corpus at the default path so the CLI picks it
       up automatically:
         /usr/share/kensa/rules/

    c) Or point at a corpus on every invocation:
         kensa check --rules-dir /path/to/your/rules <host>

  If you installed kensa with --skip-recommends or by passing a single
  .rpm/.deb on the command line, the kensa-rules package would not
  have been pulled in automatically. The kensa-rules package is noarch
  and small (~200 KB).

EOF

# Exit 0 so the package install still succeeds — the corpus is a
# soft requirement at install time, hard requirement at run time. We
# don't want the rpm/deb install to fail just because the operator
# hasn't picked their corpus yet.
exit 0
