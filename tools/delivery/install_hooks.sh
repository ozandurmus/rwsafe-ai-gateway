#!/usr/bin/env bash
# Installs the committed git hooks once per checkout (run by a human, not by an agent): privacy gate and whitespace
# check on pre-commit. Sets core.hooksPath for this repository only.
set -eu
REPO=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$REPO/.githooks"
cat > "$REPO/.githooks/pre-commit" <<'HOOK'
#!/usr/bin/env bash
set -eu
ROOT=$(git rev-parse --show-toplevel)
python3 "$ROOT/tools/privacy/repository_privacy_check.py" "$ROOT" || { echo "privacy gate FAIL: nothing committed" >&2; exit 1; }
git diff --cached --check || { echo "whitespace or conflict marker: nothing committed" >&2; exit 1; }
HOOK
chmod +x "$REPO/.githooks/pre-commit"
git -C "$REPO" config core.hooksPath .githooks
echo "hooks installed (core.hooksPath=.githooks)"
