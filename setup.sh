#!/usr/bin/env bash
set -euo pipefail

# For interactive install (curl | bash), redirect stdin from tty
# Skip for non-interactive modes (update, uninstall, install-config, remove-config, certbot, harden-sshd,
# systemctl, apt, apt-get, nft, iptables, ip6tables, ufw, firewall-cmd, fail2ban-client, netfilter-persistent)
if [ "${1:-}" != "update" ] && [ "${1:-}" != "uninstall" ] && \
   [ "${1:-}" != "install-config" ] && [ "${1:-}" != "remove-config" ] && \
   [ "${1:-}" != "certbot" ] && [ "${1:-}" != "harden-sshd" ] && \
   [ "${1:-}" != "systemctl" ] && [ "${1:-}" != "apt" ] && [ "${1:-}" != "apt-get" ] && \
   [ "${1:-}" != "nft" ] && [ "${1:-}" != "iptables" ] && [ "${1:-}" != "ip6tables" ] && \
   [ "${1:-}" != "ufw" ] && [ "${1:-}" != "firewall-cmd" ] && \
   [ "${1:-}" != "fail2ban-client" ] && [ "${1:-}" != "netfilter-persistent" ] && \
   [ ! -t 0 ] && [ -e /dev/tty ]; then
  exec </dev/tty
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must run as root (use: sudo bash setup.sh)." >&2
  exit 1
fi

INSTALL_DIR="/opt/cakeagent"
SERVICE_USER="cakeagent"
SERVICE_NAME="cakeagent"
HELPER_DIR="/usr/local/lib/cakeagent"
HELPER="$HELPER_DIR/setup.sh"
BASH_BIN="$(command -v bash || echo /usr/bin/bash)"

# The agent may invoke only these setup.sh subcommands through sudo. In
# particular it may not run `update` or `uninstall`: those mutate the
# installation and are human/root operations.
write_sudoers() {
  local file="/etc/sudoers.d/$SERVICE_NAME"
  cat <<SUDOERS > "$file"
$SERVICE_USER ALL=(ALL) NOPASSWD: \\
  $BASH_BIN $HELPER install-config *, \\
  $BASH_BIN $HELPER remove-config *, \\
  $BASH_BIN $HELPER certbot *, \\
  $BASH_BIN $HELPER harden-sshd, \\
  $BASH_BIN $HELPER systemctl *, \\
  $BASH_BIN $HELPER apt *, \\
  $BASH_BIN $HELPER apt-get *, \\
  $BASH_BIN $HELPER nft *, \\
  $BASH_BIN $HELPER iptables *, \\
  $BASH_BIN $HELPER ip6tables *, \\
  $BASH_BIN $HELPER ufw *, \\
  $BASH_BIN $HELPER firewall-cmd *, \\
  $BASH_BIN $HELPER fail2ban-client *, \\
  $BASH_BIN $HELPER netfilter-persistent *
Defaults:$SERVICE_USER !requiretty
Defaults:$SERVICE_USER env_keep += "DEBIAN_FRONTEND"
SUDOERS
  chmod 440 "$file"
  if ! visudo -cf "$file" >/dev/null 2>&1; then
    echo "   ❌ Sudoers syntax error — removing broken file"
    rm -f "$file"
    return 1
  fi
}

# Install the root-owned helper copy. The repository itself is owned by the
# service user, so pointing sudoers at /opt/cakeagent/setup.sh would let a
# compromised agent edit the helper and then execute it as root.
install_helper() {
  install -d -m 0755 "$HELPER_DIR"
  install -m 0755 -o root -g root "$INSTALL_DIR/setup.sh" "$HELPER"
}

# --- Shared: validate a target path for install-config / remove-config ---
# Writes error to stderr and returns 1 on failure, 0 on success.
validate_config_path() {
  local target="$1"

  # Reject empty, relative, whitespace/control characters, and paths containing
  # traversal components.
  case "$target" in
    ''|*[[:space:]]*) echo "Denied: invalid path" >&2; return 1 ;;
    /*) ;;
    *) echo "Denied: path must be absolute" >&2; return 1 ;;
  esac
  case "$target" in
    *..*|*/./*|*//*) echo "Denied: path traversal or normalization issue in: $target" >&2; return 1 ;;
  esac

  # Hard-deny on the most critical files — even if a prefix allowlists them
  case "$target" in
    /etc/sudoers|/etc/sudoers.d|/etc/sudoers.d/*|\
    /etc/shadow|/etc/shadow-|/etc/gshadow|/etc/gshadow-|\
    /etc/passwd|/etc/passwd-|/etc/group|/etc/group-|\
    /etc/ssh|/etc/ssh/*|\
    /etc/pam.d|/etc/pam.d/*|/etc/security|/etc/security/*|\
    /etc/ld.so.preload|/etc/ld.so.conf|/etc/ld.so.conf.d/*|\
    /etc/profile|/etc/profile.d/*|/etc/bash.bashrc|/etc/environment|\
    /etc/cron.d/*|/etc/cron.daily/*|/etc/cron.hourly/*|/etc/cron.monthly/*|/etc/cron.weekly/*|/etc/crontab|\
    /etc/hosts|/etc/hostname|/etc/resolv.conf|/etc/fstab|/etc/nsswitch.conf|\
    /etc/apt/sources.list|/etc/apt/trusted.gpg*|\
    /etc/systemd/system/cakeagent*|\
    /etc/sysctl.conf)
      echo "Denied: critical file: $target" >&2
      return 1
      ;;
  esac

  # Allowlist of directories where writes are permitted
  case "$target" in
    /etc/nginx/sites-available/*|/etc/nginx/sites-enabled/*|\
    /etc/nginx/conf.d/*|/etc/nginx/snippets/*|/etc/nginx/modules-available/*|\
    /etc/apache2/sites-available/*|/etc/apache2/sites-enabled/*|/etc/apache2/conf-available/*|\
    /etc/caddy/*|\
    /etc/systemd/system/*.service|/etc/systemd/system/*.timer|/etc/systemd/system/*.socket|\
    /etc/systemd/system/*.path|/etc/systemd/system/*.mount|/etc/systemd/system/*.target|\
    /etc/systemd/system/*.conf.d/*.conf|\
    /etc/systemd/resolved.conf.d/*.conf|/etc/systemd/network/*|\
    /etc/letsencrypt/cli.ini|/etc/letsencrypt/renewal-hooks/*/*|\
    /etc/sysctl.d/*.conf|\
    /etc/apt/sources.list.d/*.list|/etc/apt/sources.list.d/*.sources|\
    /etc/apt/preferences.d/*|/etc/apt/keyrings/*|/etc/apt/apt.conf.d/*|\
    /etc/prometheus/*|/etc/grafana/*|/etc/alertmanager/*|\
    /etc/logrotate.d/*|\
    /etc/default/*|\
    /etc/mysql/conf.d/*|/etc/mysql/mariadb.conf.d/*|\
    /etc/postgresql/*/main/conf.d/*|\
    /etc/redis/*.conf|\
    /etc/fail2ban/jail.d/*|/etc/fail2ban/filter.d/*|/etc/fail2ban/action.d/*|\
    /etc/ufw/applications.d/*|\
    /etc/nftables.d/*|/etc/nftables.conf)
      ;;
    *)
      echo "Denied: path not in allowlist: $target" >&2
      echo "Allowed prefixes include: /etc/nginx/, /etc/systemd/system/*.service, /etc/sysctl.d/, /etc/apt/sources.list.d/, /etc/logrotate.d/, etc. See setup.sh validate_config_path." >&2
      return 1
      ;;
  esac

  return 0
}

# --- install-config: write a config file to /etc/ with path validation ---
# Usage:
#   sudo bash setup.sh install-config <target>                  # content from stdin
#   sudo bash setup.sh install-config <target> <source-file>    # copy from source
# The file-input form lets agents avoid embedding nginx-style `{...;...}` in
# shell commands (the bash hook treats those as brace groups). Write the
# content with the Write tool first, then install it. Sources must be in the
# agent-writable data/tmp/ (or the service's private /tmp) so the helper cannot
# copy settings.json, memory, the database, or conversation archives into a
# world-readable /etc file.
if [ "${1:-}" = "install-config" ]; then
  TARGET="${2:-}"
  SOURCE="${3:-}"
  if ! validate_config_path "$TARGET"; then
    exit 1
  fi
  # Reject directory-shaped targets (trailing slash, no filename).
  case "$TARGET" in */) echo "Denied: target must be a file, not a directory: $TARGET" >&2; exit 1 ;; esac
  SOURCE_FD=""
  if [ -n "$SOURCE" ]; then
    case "$SOURCE" in *..*) echo "Denied: path traversal in source: $SOURCE" >&2; exit 1 ;; esac
    if [ ! -f "$SOURCE" ]; then
      echo "Source file not found: $SOURCE" >&2
      exit 1
    fi
    # Open first, then verify the opened descriptor rather than re-reading a
    # path that a same-user process could swap for a symlink to .env. This
    # closes the realpath/read TOCTOU window.
    exec {SOURCE_FD}< "$SOURCE"
    SOURCE_REAL=$(readlink -f "/proc/self/fd/$SOURCE_FD")
    case "$SOURCE_REAL" in
      "$INSTALL_DIR"/data/tmp/*|/tmp/*) ;;
      *) echo "Denied: source resolves outside $INSTALL_DIR/data/tmp/ or /tmp/: $SOURCE_REAL" >&2; exit 1 ;;
    esac
    if [ ! -f "/proc/self/fd/$SOURCE_FD" ]; then
      echo "Denied: source is not a regular file: $SOURCE_REAL" >&2
      exit 1
    fi
  fi
  PARENT="$(dirname "$TARGET")"
  mkdir -p "$PARENT"
  # Validate the resolved target as well: a symlinked parent (for example a
  # sites-enabled symlink pointing at /etc/ssh) must not redirect this write.
  TARGET_REAL="$(readlink -f -- "$TARGET" 2>/dev/null || true)"
  if [ -n "$TARGET_REAL" ] && [ "$TARGET_REAL" != "$TARGET" ]; then
    if ! validate_config_path "$TARGET_REAL"; then
      echo "Denied: target resolves to a disallowed path: $TARGET_REAL" >&2
      exit 1
    fi
  fi
  TMP="$(mktemp "${TARGET}.XXXXXX.tmp")"
  trap 'rm -f "$TMP"' EXIT
  if [ -n "$SOURCE_FD" ]; then
    head -c $((1024 * 1024 + 1)) <&"$SOURCE_FD" > "$TMP"
    exec {SOURCE_FD}<&-
  else
    head -c $((1024 * 1024 + 1)) > "$TMP"
  fi
  if [ "$(wc -c < "$TMP")" -gt $((1024 * 1024)) ]; then
    echo "Denied: config content exceeds the 1 MiB limit" >&2
    exit 1
  fi
  chmod 0644 "$TMP"
  mv "$TMP" "$TARGET"
  trap - EXIT
  echo "Wrote $TARGET ($(wc -c < "$TARGET") bytes)"
  exit 0
fi

# --- remove-config: delete a file in /etc/ with the same path validation ---
# Usage: sudo bash setup.sh remove-config <absolute-path>
if [ "${1:-}" = "remove-config" ]; then
  TARGET="${2:-}"
  if ! validate_config_path "$TARGET"; then
    exit 1
  fi
  if [ ! -e "$TARGET" ]; then
    echo "Not found: $TARGET" >&2
    exit 1
  fi
  if [ ! -f "$TARGET" ]; then
    echo "Denied: only regular files may be removed: $TARGET" >&2
    exit 1
  fi
  TARGET_REAL="$(readlink -f -- "$TARGET" 2>/dev/null || true)"
  if [ -n "$TARGET_REAL" ] && [ "$TARGET_REAL" != "$TARGET" ]; then
    if ! validate_config_path "$TARGET_REAL"; then
      echo "Denied: target resolves to a disallowed path: $TARGET_REAL" >&2
      exit 1
    fi
  fi
  rm -f "$TARGET"
  echo "Removed $TARGET"
  exit 0
fi

# --- certbot: wrap certbot with dangerous flags stripped ---
# Sudoers allows only the root-owned helper's certbot subcommand, inheriting root.
# Hook flags (--pre-hook, --post-hook, --deploy-hook, --renew-hook,
# --manual-auth-hook, --manual-cleanup-hook) are denied because they exec
# arbitrary commands as root. Instead, drop scripts into
# /etc/letsencrypt/renewal-hooks/{pre,deploy,post}/ via install-config —
# that path is allowlisted and atomically written.
# Path-redirection flags (--config, --config-dir, --work-dir, --logs-dir)
# are denied too — they could redirect certbot writes outside /etc/letsencrypt.
if [ "${1:-}" = "certbot" ]; then
  shift
  for arg in "$@"; do
    case "$arg" in
      --pre-hook|--post-hook|--deploy-hook|--renew-hook|--manual-auth-hook|--manual-cleanup-hook)
        echo "Denied: $arg — use /etc/letsencrypt/renewal-hooks/{pre,deploy,post}/ via install-config instead" >&2
        exit 1
        ;;
      --pre-hook=*|--post-hook=*|--deploy-hook=*|--renew-hook=*|--manual-auth-hook=*|--manual-cleanup-hook=*)
        echo "Denied: ${arg%%=*} — use /etc/letsencrypt/renewal-hooks/{pre,deploy,post}/ via install-config instead" >&2
        exit 1
        ;;
      -c|--config|--config-dir|--work-dir|--logs-dir|--cert-path|--key-path|--chain-path|--fullchain-path|--csr|\
      --nginx-ctl|--nginx-server-root|--apache-ctl|--apache-bin|--apache-server-root)
        echo "Denied: $arg — path redirection not allowed (certbot must use default /etc/letsencrypt layout)" >&2
        exit 1
        ;;
      -c=*|-c/*|--config=*|--config-dir=*|--work-dir=*|--logs-dir=*|--cert-path=*|--key-path=*|--chain-path=*|--fullchain-path=*|--csr=*|\
      --nginx-ctl=*|--nginx-server-root=*|--apache-ctl=*|--apache-bin=*|--apache-server-root=*)
        echo "Denied: ${arg%%=*} — path redirection not allowed" >&2
        exit 1
        ;;
    esac
  done
  if ! command -v certbot >/dev/null 2>&1; then
    echo "certbot not installed — run: sudo apt-get install -y certbot python3-certbot-nginx" >&2
    exit 1
  fi
  exec certbot "$@"
fi

# --- harden-sshd: install a known-safe hardening drop-in and reload sshd ---
# Writes /etc/ssh/sshd_config.d/99-cakeagent-hardening.conf with a fixed,
# vetted ruleset (no user input — no foot-gun), validates the combined
# config via `sshd -t`, then reloads sshd. On validation failure, the
# drop-in is reverted to its previous contents (or deleted if new).
#
# Rationale: letting the agent write arbitrary sshd_config.d/*.conf would
# allow directives like Port, ListenAddress, AuthorizedKeysFile,
# PermitRootLogin, or Match blocks to weaken auth or enable lockout. A
# fixed-content helper bounds the blast radius while still letting the
# agent complete a common admin task ("harden SSH") on request.
if [ "${1:-}" = "harden-sshd" ]; then
  DROPIN="/etc/ssh/sshd_config.d/99-cakeagent-hardening.conf"
  BACKUP=""
  if [ -f "$DROPIN" ]; then
    BACKUP="$(mktemp "${DROPIN}.bak.XXXXXX")"
    cp -a "$DROPIN" "$BACKUP"
  fi
  mkdir -p /etc/ssh/sshd_config.d

  # Check for at least one authorized_keys file before disabling password auth.
  # This prevents locking out password-only users. We check all users' home
  # directories and root.
  has_authorized_keys=0
  for homedir in /root /home/*; do
    if [ -f "$homedir/.ssh/authorized_keys" ] && [ -s "$homedir/.ssh/authorized_keys" ]; then
      has_authorized_keys=1
      break
    fi
  done
  # Also check for any user with SSH keys in /etc/ssh/authorized_keys (centralized)
  if [ "$has_authorized_keys" -eq 0 ] && [ -f /etc/ssh/authorized_keys ] && [ -s /etc/ssh/authorized_keys ]; then
    has_authorized_keys=1
  fi
  if [ "$has_authorized_keys" -eq 0 ]; then
    echo "Error: No authorized_keys found for any user. Refusing to disable PasswordAuthentication." >&2
    echo "At least one user must have ~/.ssh/authorized_keys with content before hardening." >&2
    exit 1
  fi

  TMP="$(mktemp "${DROPIN}.XXXXXX.tmp")"
  trap 'rm -f "$TMP"; [ -n "$BACKUP" ] && rm -f "$BACKUP"' EXIT
  cat > "$TMP" <<'HARDENING'
# Managed by CakeAgent (setup.sh harden-sshd). Do not edit manually.
# Disables password auth, root login, agent forwarding, and limits auth attempts.
PermitRootLogin prohibit-password
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
PubkeyAuthentication yes
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PermitTunnel no
HARDENING
  chmod 0644 "$TMP"
  mv "$TMP" "$DROPIN"
  if ! sshd -t 2>&1; then
    echo "sshd -t failed after installing $DROPIN — reverting" >&2
    if [ -n "$BACKUP" ]; then
      mv "$BACKUP" "$DROPIN"
      BACKUP=""
    else
      rm -f "$DROPIN"
    fi
    trap - EXIT
    exit 1
  fi
  [ -n "$BACKUP" ] && rm -f "$BACKUP"
  trap - EXIT
  # Reload via systemctl — ssh.service ExecReload runs `sshd -t` first on
  # Debian/Ubuntu, so a broken reload won't kill the running daemon.
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
  echo "Installed $DROPIN and reloaded sshd"
  exit 0
fi

# --- Update (pulls code, builds, refreshes service, restarts) ---
if [ "${1:-}" = "update" ]; then
  echo "🍰 Updating CakeAgent..."
  cd "$INSTALL_DIR"
  if [ -n "$(sudo -u "$SERVICE_USER" git status --porcelain --untracked-files=no)" ]; then
    echo "   ❌ Working tree has local changes — commit or stash them first." >&2
    exit 1
  fi
  BEFORE=$(sudo -u "$SERVICE_USER" git rev-parse HEAD)
  NODE_DIR=$(dirname "$(command -v node)")
  NODE_BIN=$(command -v node)
  sudo -u "$SERVICE_USER" git pull --ff-only
  AFTER=$(sudo -u "$SERVICE_USER" git rev-parse HEAD)
  if [ "$BEFORE" != "$AFTER" ]; then
    if ! sudo -u "$SERVICE_USER" bash -c "export PATH='$NODE_DIR':\$PATH && npm ci --no-fund --no-audit && npm run build"; then
      echo "   ❌ Build failed — rolling back to previous version"
      sudo -u "$SERVICE_USER" git reset --hard "$BEFORE"
      exit 1
    fi
  else
    echo "   No changes."
  fi
  # Refresh the root-owned helper, sudoers, and service file. Skip if /etc is
  # read-only (e.g. invoked from inside the systemd sandbox).
  if touch /etc/sudoers.d/.writetest 2>/dev/null; then
    rm -f /etc/sudoers.d/.writetest
    install_helper
    sed -e "s|/opt/cakeagent|${INSTALL_DIR}|g" \
        -e "s|^ExecStart=/usr/bin/node |ExecStart=${NODE_BIN} |" \
        -e "s|User=cakeagent|User=${SERVICE_USER}|g" \
        -e "s|Group=cakeagent|Group=${SERVICE_USER}|g" \
        -e "/\[Service\]/a Environment=PATH=${NODE_DIR}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
        "$INSTALL_DIR/cakeagent.service" > "/etc/systemd/system/${SERVICE_NAME}.service"
    write_sudoers || exit 1
    systemctl daemon-reload
  fi
  if [ "$BEFORE" != "$AFTER" ]; then
    # Restart if we can (SSH context). Inside systemd sandbox, the caller handles restart.
    systemctl restart "$SERVICE_NAME" 2>/dev/null && echo "✅ Updated and restarted." || echo "✅ Updated and built. Restart pending."
  else
    echo "✅ No changes."
  fi
  exit 0
fi

# --- Uninstall ---
if [ "${1:-}" = "uninstall" ]; then
  echo "🍰 CakeAgent — Uninstall"
  echo ""
  echo "   This will completely remove CakeAgent and revert the system:"
  echo "   - Stop and remove systemd service"
  echo "   - Delete $INSTALL_DIR (code, data, config, everything)"
  echo "   - Delete system user '$SERVICE_USER' and its home"
  echo "   - Remove sudoers entry"
  echo "   - Remove any packages the agent installed (ffmpeg, whisper.cpp, Python venv)"
  echo ""
  read -rp "   Type 'yes' to confirm: " CONFIRM
  if [ "$CONFIRM" != "yes" ]; then
    echo "   Cancelled."
    exit 0
  fi

  echo ""

  sudo systemctl stop "$SERVICE_NAME" 2>/dev/null || true
  sudo systemctl disable "$SERVICE_NAME" 2>/dev/null || true
  sudo rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
  sudo systemctl daemon-reload 2>/dev/null || true
  echo "   ✅ Service removed"

  sudo rm -f "/etc/sudoers.d/$SERVICE_NAME"
  sudo rm -rf "$HELPER_DIR"
  echo "   ✅ Sudoers entry and root helper removed"

  if id "$SERVICE_USER" &>/dev/null; then
    sudo userdel "$SERVICE_USER" 2>/dev/null || true
    echo "   ✅ User '$SERVICE_USER' removed"
  fi

  sudo rm -rf "$INSTALL_DIR"
  echo "   ✅ $INSTALL_DIR removed"

  echo ""
  echo "🧹 Fully uninstalled."
  exit 0
fi

# --- systemctl: safe service management wrapper ---
# Only allows specific verbs on non-critical units. Blocks stop/restart/disable/mask
# on ssh/sshd/networking and any operation on cakeagent itself.
if [ "${1:-}" = "systemctl" ]; then
  shift
  VERB="${1:-}"
  UNIT="${2:-}"

  # Always allow these read-only verbs
  case "$VERB" in
    status|is-active|is-enabled|is-failed|list-units|list-unit-files|daemon-reload)
      systemctl "$VERB" "$UNIT"
      exit $?
      ;;
  esac

  # Block all operations on cakeagent unit (no self-management)
  case "$UNIT" in
    cakeagent*|"$SERVICE_NAME"*)
      echo "Denied: operations on cakeagent unit are not allowed" >&2
      exit 1
      ;;
  esac

  # Block destructive verbs on critical units
  case "$VERB" in
    stop|restart|disable|enable|mask|unmask|kill)
      case "$UNIT" in
        ssh|sshd|sshd.service|ssh.socket|sshd.socket|networking|networking.service)
          echo "Denied: $VERB on critical unit $UNIT" >&2
          exit 1
          ;;
      esac
      ;;
  esac

  # Allow other verbs (start, reload, etc.) on non-critical units
  case "$VERB" in
    start|reload|enable|disable|mask|unmask|restart|stop|kill)
      systemctl "$VERB" "$UNIT"
      exit $?
      ;;
    *)
      echo "Denied: unknown systemctl verb: $VERB" >&2
      exit 1
      ;;
  esac
fi

# --- apt: safe package management wrapper ---
# Allows install, update, upgrade. Blocks remove/purge of critical packages.
if [ "${1:-}" = "apt" ] || [ "${1:-}" = "apt-get" ]; then
  shift
  VERB="${1:-}"

  # Allow read-only verbs
  case "$VERB" in
    update|list|search|show|policy|autoclean|autoremove)
      apt "$VERB" "$@"
      exit $?
      ;;
  esac

  # Allow install/upgrade with package validation
  case "$VERB" in
    install|upgrade|full-upgrade|dist-upgrade)
      shift
      for pkg in "$@"; do
        # Block removal of critical packages via install of conflicting packages
        case "$pkg" in
          *cakeagent*|*sshd*|*openssh-server*|*sudo*|*systemd*|*libc6*|*grub*|*kernel*|*linux-image*)
            echo "Denied: installing/upgrading critical package: $pkg" >&2
            exit 1
            ;;
        esac
      done
      DEBIAN_FRONTEND=noninteractive apt "$VERB" -y "$@"
      exit $?
      ;;
    remove|purge|autoremove)
      # Block removal of critical packages
      shift
      for pkg in "$@"; do
        case "$pkg" in
          *cakeagent*|*sshd*|*openssh-server*|*sudo*|*systemd*|*libc6*|*grub*|*kernel*|*linux-image*)
            echo "Denied: removing critical package: $pkg" >&2
            exit 1
            ;;
        esac
      done
      DEBIAN_FRONTEND=noninteractive apt "$VERB" -y "$@"
      exit $?
      ;;
    *)
      echo "Denied: unknown apt verb: $VERB" >&2
      exit 1
      ;;
  esac
fi

# --- nft: safe nftables wrapper ---
# Allows rule/chain/set add/delete/list. Blocks flush/delete table.
if [ "${1:-}" = "nft" ]; then
  shift
  # Check for destructive operations
  for arg in "$@"; do
    case "$arg" in
      flush|delete)
        # Next arg determines what's being flushed/deleted
        ;;
    esac
  done
  # Simple deny-list for destructive verbs at top level
  case "$1" in
    flush)
      echo "Denied: nft flush not allowed (use delete rule/chain/set instead)" >&2
      exit 1
      ;;
    delete)
      # Allow delete rule/chain/set, but not delete table
      if [ "${2:-}" = "table" ]; then
        echo "Denied: nft delete table not allowed" >&2
        exit 1
      fi
      ;;
  esac
  nft "$@"
  exit $?
fi

# --- iptables / ip6tables: safe wrapper ---
# Blocks -F/-X/-Z (flush/delete/zero) and -P ACCEPT (default accept policy)
if [ "${1:-}" = "iptables" ] || [ "${1:-}" = "ip6tables" ]; then
  CMD="${1}"
  shift
  for arg in "$@"; do
    case "$arg" in
      -F|-X|-Z)
        echo "Denied: $CMD $arg (flush/delete/zero not allowed)" >&2
        exit 1
        ;;
      -P)
        # Next arg is chain, then policy - check for ACCEPT
        ;;
    esac
  done
  # Check for -P ... ACCEPT pattern
  for i in $(seq 1 $#); do
    if [ "${!i}" = "-P" ]; then
      next=$((i + 1))
      if [ "${!next:-}" = "ACCEPT" ]; then
        echo "Denied: $CMD -P ... ACCEPT (default accept policy not allowed)" >&2
        exit 1
      fi
    fi
  done
  # Block rules touching port 22
  for arg in "$@"; do
    case "$arg" in
      *22*)
        # Could be --dport 22, --sport 22, etc.
        if [[ "$arg" =~ (dport|sport|port)[[:space:]]*22\b ]]; then
          echo "Denied: $CMD rule touching port 22" >&2
          exit 1
        fi
        ;;
    esac
  done
  "$CMD" "$@"
  exit $?
fi

# --- ufw: safe wrapper ---
# Allows rule management, status, reload. Blocks reset, disable, default allow, port 22 rules.
if [ "${1:-}" = "ufw" ]; then
  shift
  VERB="${1:-}"
  # Handle multi-word verbs first
  case "$VERB $2" in
    "status verbose"|"status numbered"|"app list"|"app info"|"app update")
      # Read-only - allow
      ufw "$VERB" "$2" "$3"
      exit $?
      ;;
  esac
  case "$VERB" in
    status|show|reload)
      ufw "$VERB" "$@"
      exit $?
      ;;
    enable|disable|reset)
      echo "Denied: ufw $VERB not allowed" >&2
      exit 1
      ;;
    allow|deny|limit|reject|delete|route|insert)
      # Check for port 22 in args
      for arg in "$@"; do
        if [[ "$arg" =~ ^22(/tcp)?$ ]] || [[ "$arg" =~ ^22(/udp)?$ ]]; then
          echo "Denied: ufw rule on port 22" >&2
          exit 1
        fi
      done
      # Check for "default allow"
      if [ "$VERB" = "default" ] && [ "${2:-}" = "allow" ]; then
        echo "Denied: ufw default allow not allowed" >&2
        exit 1
      fi
      ufw "$VERB" "$@"
      exit $?
      ;;
    default)
      if [ "${2:-}" = "allow" ]; then
        echo "Denied: ufw default allow not allowed" >&2
        exit 1
      fi
      ufw "$VERB" "$@"
      exit $?
      ;;
    *)
      echo "Denied: unknown ufw verb: $VERB" >&2
      exit 1
      ;;
  esac
fi

# --- firewall-cmd: safe wrapper ---
# Allows zone/port/service management. Blocks panic-on, remove-service=ssh, remove-port=22, set-default-zone=trusted.
if [ "${1:-}" = "firewall-cmd" ]; then
  shift
  for arg in "$@"; do
    case "$arg" in
      --panic-on|--remove-service=ssh|--remove-port=22*|--set-default-zone=trusted)
        echo "Denied: firewall-cmd $arg" >&2
        exit 1
        ;;
    esac
  done
  firewall-cmd "$@"
  exit $?
fi

# --- fail2ban-client: safe wrapper ---
# Allows status, set, get, unban <ip>, reload. Blocks stop, unban --all.
if [ "${1:-}" = "fail2ban-client" ]; then
  shift
  VERB="${1:-}"
  case "$VERB" in
    stop)
      echo "Denied: fail2ban-client stop not allowed" >&2
      exit 1
      ;;
    unban)
      if [ "${2:-}" = "--all" ]; then
        echo "Denied: fail2ban-client unban --all not allowed" >&2
        exit 1
      fi
      fail2ban-client "$VERB" "$@"
      exit $?
      ;;
    status|set|get|reload)
      fail2ban-client "$VERB" "$@"
      exit $?
      ;;
    *)
      echo "Denied: unknown fail2ban-client verb: $VERB" >&2
      exit 1
      ;;
  esac
fi

# --- netfilter-persistent: safe wrapper ---
# Allows save, reload. Blocks flush.
if [ "${1:-}" = "netfilter-persistent" ]; then
  shift
  VERB="${1:-}"
  case "$VERB" in
    flush)
      echo "Denied: netfilter-persistent flush not allowed" >&2
      exit 1
      ;;
    save|reload)
      netfilter-persistent "$VERB"
      exit $?
      ;;
    *)
      echo "Denied: unknown netfilter-persistent verb: $VERB" >&2
      exit 1
      ;;
  esac
fi

# --- Install ---

echo "🍰 CakeAgent Setup"
echo "==================="
echo ""

echo "1️⃣  Checking prerequisites..."

if ! command -v node &>/dev/null; then
  echo "   ❌ Node.js 22+ required (better-sqlite3 uses Node 22 APIs). Install: https://nodejs.org"
  exit 1
fi
NODE_VER=$(node -v | sed 's/v//' | cut -d. -f1)
if [ "$NODE_VER" -lt 22 ]; then
  echo "   ❌ Node.js 22+ required (found $(node -v))"
  exit 1
fi
echo "   ✅ Node.js $(node -v)"

echo ""
echo "2️⃣  Creating system user..."

sudo mkdir -p "$INSTALL_DIR"
if id "$SERVICE_USER" &>/dev/null; then
  echo "   ✅ User '$SERVICE_USER' exists"
else
  sudo useradd -r -d "$INSTALL_DIR" -s /usr/sbin/nologin "$SERVICE_USER"
  echo "   ✅ Created user '$SERVICE_USER'"
fi
sudo chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"

echo ""
echo "3️⃣  Installing to $INSTALL_DIR..."

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ "$SCRIPT_DIR" != "$INSTALL_DIR" ]; then
  sudo cp -a "$SCRIPT_DIR"/. "$INSTALL_DIR/"
  sudo chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
fi

echo ""
echo "4️⃣  Installing dependencies..."

NPM_BIN=$(command -v npm)
NODE_DIR=$(dirname "$(command -v node)")

sudo -u "$SERVICE_USER" bash -c "export PATH='$NODE_DIR':\$PATH && cd '$INSTALL_DIR' && '$NPM_BIN' ci --no-fund --no-audit 2>&1" | tail -3
echo "   Building..."
sudo -u "$SERVICE_USER" bash -c "export PATH='$NODE_DIR':\$PATH && cd '$INSTALL_DIR' && '$NPM_BIN' run build" || {
  echo "   ❌ Build failed"
  exit 1
}
echo "   ✅ Built"

echo ""
echo "5️⃣  Configuring agent permissions..."

install_helper
write_sudoers || exit 1
echo "   ✅ Agent can install system packages with a scoped sudo policy"

sudo -u "$SERVICE_USER" mkdir -p "$INSTALL_DIR/data" "$INSTALL_DIR/groups/main" "$INSTALL_DIR/credentials"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "6️⃣  Telegram bot setup:"
echo ""
echo "   → Create a bot: https://t.me/BotFather (send /newbot)"
echo ""
read -rsp "   Bot token: " BOT_TOKEN
echo ""

if [ -z "$BOT_TOKEN" ]; then
  echo "   ❌ Required"
  exit 1
fi
if ! [[ "$BOT_TOKEN" =~ ^[0-9]+:[A-Za-z0-9_-]+$ ]]; then
  echo "   ❌ Invalid bot token format"
  exit 1
fi

echo "   Validating..."
RESULT=$(curl -sf "https://api.telegram.org/bot${BOT_TOKEN}/getMe" 2>/dev/null || echo '{"ok":false}')
if echo "$RESULT" | grep -q '"ok":true'; then
  BOT_NAME=$(echo "$RESULT" | grep -o '"first_name":"[^"]*"' | cut -d'"' -f4)
  echo "   ✅ $BOT_NAME"
else
  echo "   ❌ Invalid token"
  exit 1
fi

echo ""
echo "   → Get your user ID: https://t.me/userinfobot"
echo ""
read -rp "   Your Telegram user ID: " CHAT_ID

if [ -z "$CHAT_ID" ]; then
  echo "   ❌ Required"
  exit 1
fi
if ! [[ "$CHAT_ID" =~ ^-?[0-9]+$ ]]; then
  echo "   ❌ Invalid Telegram chat ID"
  exit 1
fi

echo ""
echo "7️⃣  Claude authentication:"
echo ""
echo "   [1] Subscription token (recommended — uses your Claude Pro/Team/Enterprise plan)"
echo "       Requires Claude Code CLI: npm install -g @anthropic-ai/claude-code"
echo "       Then run in another terminal: claude setup-token"
echo "       It will display a token starting with sk-ant-oat... (valid 1 year)"
echo ""
echo "   [2] API key (pay-per-use billing)"
echo "       Create one at: https://console.anthropic.com/settings/keys"
echo "       Starts with sk-ant-api..."
echo ""
read -rp "   Choose [1/2]: " AUTH_CHOICE

AUTH_KEY=""
AUTH_VAR=""
if [ "$AUTH_CHOICE" = "2" ]; then
  echo ""
  echo "   → https://console.anthropic.com/settings/keys"
  echo "   → Click 'Create Key', copy the sk-ant-api... value"
  echo ""
  read -rsp "   API key: " AUTH_KEY
echo ""
  AUTH_VAR="ANTHROPIC_API_KEY"
else
  echo ""
  echo "   In another terminal, run:"
  echo ""
  echo "     npm install -g @anthropic-ai/claude-code"
  echo "     claude setup-token"
  echo ""
  echo "   Copy the sk-ant-oat... token it displays and paste below."
  echo ""
  read -rsp "   Subscription token: " AUTH_KEY
echo ""
  AUTH_VAR="CLAUDE_CODE_OAUTH_TOKEN"
fi

if [ -z "$AUTH_KEY" ]; then
  echo "   ⚠️  No auth provided. Add it to $INSTALL_DIR/.env before starting."
elif ! [[ "$AUTH_KEY" =~ ^[A-Za-z0-9_.:-]+$ ]]; then
  echo "   ❌ Invalid auth key format"
  exit 1
else
  if [ ${#AUTH_KEY} -gt 14 ]; then
    MASKED="${AUTH_KEY:0:10}$(printf '*%.0s' $(seq 1 $((${#AUTH_KEY} - 14))))${AUTH_KEY: -4}"
  else
    MASKED="${AUTH_KEY:0:4}****"
  fi
  echo "   ✅ $MASKED"
fi

ENV_FILE="$INSTALL_DIR/.env"
{
  echo "TELEGRAM_BOT_TOKEN=${BOT_TOKEN}"
  echo "TELEGRAM_CHAT_ID=${CHAT_ID}"
  if [ -n "$AUTH_KEY" ]; then
    echo "${AUTH_VAR}=${AUTH_KEY}"
  fi
} | sudo tee "$ENV_FILE" > /dev/null

sudo chown root:root "$ENV_FILE"
sudo chmod 600 "$ENV_FILE"
echo ""
echo "   ✅ Configuration saved"

echo ""
echo "8️⃣  Starting service..."

NODE_PATH_DIR=$(dirname "$(command -v node)")
NODE_BIN=$(command -v node)
sed -e "s|/opt/cakeagent|${INSTALL_DIR}|g" \
    -e "s|^ExecStart=/usr/bin/node |ExecStart=${NODE_BIN} |" \
    -e "s|User=cakeagent|User=${SERVICE_USER}|g" \
    -e "s|Group=cakeagent|Group=${SERVICE_USER}|g" \
    -e "/\[Service\]/a Environment=PATH=${NODE_PATH_DIR}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    "$INSTALL_DIR/cakeagent.service" | sudo tee "/etc/systemd/system/${SERVICE_NAME}.service" > /dev/null

sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE_NAME"
sudo systemctl start "$SERVICE_NAME"

echo "   ✅ Running"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🎉 CakeAgent is running!"
echo ""
echo "   Send a message to your bot on Telegram."
echo "   On first message, it guides you through personalization."
echo ""
echo "   Logs:      sudo journalctl -u $SERVICE_NAME -f"
echo "   Restart:   /restart (via Telegram)"
echo "   Uninstall: sudo bash setup.sh uninstall"
