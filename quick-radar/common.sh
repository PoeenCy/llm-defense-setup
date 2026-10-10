#!/usr/bin/env bash
# Shared data-only config loader. The Python helper emits fixed keys with shlex.quote.
GD1_DEF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
gd1_load_config() {
    local file="${GD1_CONFIG:-$GD1_DEF_DIR/../config.env}" exports
    if [[ ! -f "$file" && -f "$GD1_DEF_DIR/config.env" ]]; then file="$GD1_DEF_DIR/config.env"; fi
    exports="$(python3 "$GD1_DEF_DIR/defense_config.py" --config "$file" --shell)" || return
    eval "$exports"
}
gd1_ssh_args() {
    GD1_SSH=(ssh -F /dev/null -p "$SSH_PORT" -o BatchMode=yes -o ConnectTimeout=5
        -o ServerAliveInterval=15 -o ServerAliveCountMax=2
        -o "StrictHostKeyChecking=$SSH_HOST_KEY_CHECKING" -o "UserKnownHostsFile=$SSH_KNOWN_HOSTS"
        -o ForwardAgent=no -o ClearAllForwardings=yes)
    if [[ -n "$SSH_KEY" ]]; then GD1_SSH+=(-i "$SSH_KEY" -o IdentitiesOnly=yes); fi
    GD1_SSH+=("$SSH_USER@$VULNBOX_IP")
}
