#!/usr/bin/env bash
# Install Jarvis Origin, and optionally run it continuously.
#
#   ./install.sh              put `jarvis-origin` on PATH
#   ./install.sh --service    ...and run the daemon as a systemd *user* service
#   ./install.sh --windows    ...and print the one Windows command that keeps
#                             WSL itself running across reboots
#
# Nothing here needs sudo, and nothing here writes outside your home directory.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$HOME/.local/bin"
PORT="${JARVIS_ORIGIN_PORT:-8790}"
STATE_DIR="$HOME/.jarvis-origin"
mkdir -p "$BIN" "$STATE_DIR"
chmod 700 "$STATE_DIR"

want_service=false; want_windows=false
for arg in "$@"; do
  case "$arg" in
    --service) want_service=true ;;
    --windows) want_windows=true ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

cat > "$BIN/jarvis-origin" <<EOF
#!/usr/bin/env bash
cd "$HERE" && exec python3 -m jarvis_origin "\$@"
EOF
chmod +x "$BIN/jarvis-origin"
echo "installed: $BIN/jarvis-origin"

case ":$PATH:" in
  *":$BIN:"*) ;;
  *) echo "note: add $BIN to PATH — echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc" ;;
esac

if $want_service; then
  UNIT="$HOME/.config/systemd/user"
  mkdir -p "$UNIT"
  cat > "$UNIT/jarvis-origin.service" <<EOF
[Unit]
Description=Jarvis Origin — process, network, injected-input and threat-intel monitoring
After=network.target

[Service]
Type=simple
WorkingDirectory=$HERE
ExecStart=/usr/bin/python3 -m jarvis_origin serve --port $PORT
Restart=on-failure
RestartSec=15

# Relative cgroup shares (max 10000); they need no privilege.
CPUWeight=1000
IOWeight=1000
# Bound the monitor so it can never become the problem it watches for.
MemoryHigh=768M
MemoryMax=1G
TasksMax=512

[Install]
WantedBy=default.target
EOF
  systemctl --user daemon-reload
  systemctl --user enable --now jarvis-origin.service
  echo "service:   systemctl --user status jarvis-origin"
  echo "logs:      journalctl --user -u jarvis-origin -f"
  echo "dashboard: http://127.0.0.1:$PORT"

  # Without linger, systemd tears down the user manager when the last shell
  # exits — which is exactly what happens when you close your terminal.
  if [ "$(loginctl show-user "$USER" -p Linger --value 2>/dev/null)" != "yes" ]; then
    echo
    echo "Note: the daemon stops when you close your last shell."
    echo "To keep it running without a login session:"
    echo "    sudo loginctl enable-linger $USER"
  fi
fi

if $want_windows; then
  cat <<'EOF'

--------------------------------------------------------------------
Keeping it running across Windows reboots
--------------------------------------------------------------------
WSL only runs while Windows keeps it running. Enabling linger (above)
keeps Jarvis Origin alive inside WSL; this task makes sure WSL itself starts
at logon, with no visible window.

Run this ONCE in Windows PowerShell (no elevation needed):

  Unregister-ScheduledTask -TaskName "WSL Jarvis Origin" `
       -Confirm:$false -ErrorAction SilentlyContinue
  $a = New-ScheduledTaskAction -Execute "wsl.exe" `
       -Argument "-d Ubuntu --exec /bin/true"
  $t = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
  $p = New-ScheduledTaskPrincipal -UserId $env:USERNAME `
       -LogonType Interactive -RunLevel Limited
  $s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
       -DontStopIfGoingOnBatteries -StartWhenAvailable `
       -ExecutionTimeLimit ([TimeSpan]::Zero)
  Register-ScheduledTask -TaskName "WSL Jarvis Origin" -Action $a `
       -Trigger $t -Principal $p -Settings $s `
       -Description "Starts WSL so Jarvis Origin keeps running"

RunLevel Limited is load-bearing: -RunLevel Highest makes registration
itself require an elevated shell and fails with 0x80070005. The task does
not need admin — it only has to start WSL.

To undo:  Unregister-ScheduledTask -TaskName "WSL Jarvis Origin"
--------------------------------------------------------------------
EOF
fi
