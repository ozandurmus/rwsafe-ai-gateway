#!/usr/bin/env bash
# Stops the local trial started by run_trial.sh, by its PID files under tools/trial/.run/. The ICAP engine and the
# control plane get SIGTERM and time for their shutdown hooks (the engine drains and ships its events, the control plane
# closes the embedded PostgreSQL); a process still alive after its bound gets SIGKILL. Idempotent; messages are Turkish.
set -u

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUN="$ROOT/tools/trial/.run"

label() {
    case "$1" in
        trial_proxy) echo "Deneme sohbet sayfası" ;;
        mock_ai) echo "Sahte sağlayıcı" ;;
        frontend) echo "Yönetim arayüzü" ;;
        dataplane) echo "Denetim motoru" ;;
        control) echo "Denetim merkezi" ;;
    esac
}

pid_of() {
    [ -f "$RUN/$1.pid" ] && cat "$RUN/$1.pid"
}

alive() {
    local pid
    pid="$(pid_of "$1")" && [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

term() {
    if alive "$1"; then
        kill -TERM "$(pid_of "$1")" 2>/dev/null
    else
        rm -f "$RUN/$1.pid"
        printf '%s zaten çalışmıyordu.\n' "$(label "$1")"
    fi
}

await() {
    local name="$1" limit="$2" waited=0
    [ -f "$RUN/$name.pid" ] || return 0
    while alive "$name" && [ "$waited" -lt "$limit" ]; do
        sleep 1
        waited=$((waited + 1))
    done
    if alive "$name"; then
        kill -KILL "$(pid_of "$name")" 2>/dev/null
        printf '%s %s saniye içinde kapanmadı, zorla durduruldu.\n' "$(label "$name")" "$limit"
    else
        printf '%s durduruldu.\n' "$(label "$name")"
    fi
    rm -f "$RUN/$name.pid"
}

# The engine first, so its last events reach the control plane; the control plane last.
for n in trial_proxy mock_ai frontend dataplane; do
    term "$n"
done
for n in trial_proxy mock_ai frontend; do
    await "$n" 10
done
await dataplane 45
term control
await control 60
rm -f "$RUN/mock_ai.port"
echo "Deneme durduruldu."
