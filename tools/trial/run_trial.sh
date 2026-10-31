#!/usr/bin/env bash
# Starts the local end-to-end trial in the background (tools/trial/README.md): the control plane with its embedded
# PostgreSQL and in-memory directory, the admin UI dev server, the ICAP engine fed by the control plane's signed snapshot,
# the fake AI provider and the trial chat page. Loopback only, no sudo, no container runtime, nothing from the internet
# (Gradle runs --offline and npm installs from its local cache; TRIAL_GRADLE_OFFLINE=0 lets Gradle download).
# Idempotent: a component whose PID file names a live process is left running. Logs and PID files: tools/trial/.run/.
# Messages are Turkish: the Product Owner reads them.
set -u

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUN="$ROOT/tools/trial/.run"
DEV="$ROOT/java/control/build/dev"
HOST=127.0.0.1
CONTROL_PORTS="8080 8091 8092 9400 ${RWSAFE_DEV_PG_PORT:-54329}"
mkdir -p "$RUN" "$RUN/spool" "$RUN/snapshot-cache"

say() { printf '%s\n' "$*"; }

fail() {
    say ""
    say "HATA: $1"
    if [ -n "${2:-}" ] && [ -f "$2" ]; then
        say "Ayrıntı için günlük dosyası: ${2#$ROOT/}"
        say "Günlüğün son satırları:"
        tail -n 15 "$2" | sed 's/^/    /'
    fi
    say "Başlatılan bileşenleri durdurmak için: tools/trial/stop_trial.sh"
    exit 1
}

alive() {
    local pidfile="$RUN/$1.pid"
    [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null
}

port_open() {
    (exec 3<>"/dev/tcp/$HOST/$1") 2>/dev/null
}

http_code() {
    curl -s -o /dev/null -m 3 -w '%{http_code}' "$1" 2>/dev/null || true
}

# Refuses to start a component whose port another process already holds.
ports_free() {
    local p
    for p in $2; do
        if port_open "$p"; then
            fail "$1 başlatılamadı: $HOST:$p portu başka bir süreç tarafından kullanılıyor (önceki bir deneme ya da elle başlatılmış bir sunucu olabilir). O süreci kapatıp yeniden deneyin."
        fi
    done
}

# start <name> <working dir> <log> <command...>: the command replaces the subshell, so the PID file names the server.
start() {
    local name="$1" dir="$2" log="$3"
    shift 3
    rm -f "$RUN/$name.pid"
    ( cd "$dir" && exec nohup "$@" ) >"$log" 2>&1 </dev/null &
    echo $! >"$RUN/$name.pid"
}

# wait_http <name> <label> <url> <seconds> <log>: bounded wait for HTTP 200 while the process stays alive.
wait_http() {
    local name="$1" label="$2" url="$3" limit="$4" log="$5" waited=0
    while [ "$waited" -lt "$limit" ]; do
        if [ "$(http_code "$url")" = "200" ]; then
            return 0
        fi
        if ! alive "$name"; then
            fail "$label beklenmedik şekilde kapandı." "$log"
        fi
        sleep 2
        waited=$((waited + 2))
    done
    fail "$label $limit saniye içinde hazır olmadı ($url)." "$log"
}

# A PID file whose process has gone is stale.
for n in control dataplane frontend mock_ai trial_proxy; do
    if [ -f "$RUN/$n.pid" ] && ! alive "$n"; then
        rm -f "$RUN/$n.pid"
    fi
done

say "rwsafe yerel deneme başlatılıyor (yalnızca $HOST üzerinde)."

# 1. Classpaths of the two Java servers, compiled offline.
if ! alive control || ! alive dataplane; then
    say "1/6 Java bileşenleri derleniyor (ilk seferde birkaç dakika sürebilir)..."
    OFFLINE="--offline"
    [ "${TRIAL_GRADLE_OFFLINE:-1}" = "0" ] && OFFLINE=""
    "$ROOT/java/gradlew" -p "$ROOT/java" $OFFLINE -q -I "$ROOT/tools/trial/classpath.init.gradle" \
        -PtrialOut="$RUN" :control:trialClasspath :dataplane:trialClasspath >"$RUN/build.log" 2>&1 \
        || fail "Derleme başarısız oldu (adım 1, Gradle)." "$RUN/build.log"
else
    say "1/6 Java bileşenleri zaten çalışıyor, derleme atlandı."
fi

# 2. Control plane (admin API 8080, snapshot feed 8091, event ingestion 8092).
if alive control; then
    say "2/6 Denetim merkezi zaten çalışıyor."
else
    say "2/6 Denetim merkezi başlatılıyor (gömülü veritabanı ve deneme dizini ile)..."
    ports_free "Denetim merkezi" "$CONTROL_PORTS"
    start control "$ROOT/java/control" "$RUN/control.log" "$(cat "$RUN/control.java")" \
        "-Drwsafe.dev.dir=$DEV" -cp "$(cat "$RUN/control.classpath")" io.rwsafe.control.dev.DevControlApplication
fi
wait_http control "Denetim merkezi (adım 2)" "http://$HOST:8080/readyz" 240 "$RUN/control.log"
[ -f "$DEV/snapshot-public-keys/dev-snapshot.pem" ] \
    || fail "Politika imzası için açık anahtar bulunamadı (adım 2)." "$RUN/control.log"

# 3. ICAP engine, fed by the signed snapshot, sending verdict events to the control plane.
if alive dataplane; then
    say "3/6 Denetim motoru zaten çalışıyor."
else
    say "3/6 Denetim motoru (ICAP) başlatılıyor..."
    ports_free "Denetim motoru" "1344 9401"
    start dataplane "$ROOT/java/dataplane" "$RUN/dataplane.log" env \
        RWSAFE_ICAP_BIND=$HOST RWSAFE_ICAP_PORT=1344 RWSAFE_METRICS_PORT=9401 \
        RWSAFE_SNAPSHOT_URL="http://$HOST:8091/internal/v1/policy/snapshot" \
        RWSAFE_SNAPSHOT_PUBLIC_KEYS="$DEV/snapshot-public-keys/dev-snapshot.pem" \
        RWSAFE_SNAPSHOT_CACHE="$RUN/snapshot-cache" \
        RWSAFE_CONTROL_EVENTS_URL="http://$HOST:8092/internal/v1/verdict-events" \
        RWSAFE_SPOOL_DIR="$RUN/spool" \
        "$(cat "$RUN/dataplane.java")" -cp "$(cat "$RUN/dataplane.classpath")" io.rwsafe.dataplane.boot.DataPlaneApplication
fi
wait_http dataplane "Denetim motoru (adım 3)" "http://$HOST:9401/ready" 90 "$RUN/dataplane.log"

# 4. Admin UI dev server (proxies /api to 8080).
if alive frontend; then
    say "4/6 Yönetim arayüzü zaten çalışıyor."
else
    if [ ! -x "$ROOT/frontend/node_modules/.bin/vite" ]; then
        say "4/6 Yönetim arayüzünün bağımlılıkları yerel npm önbelleğinden kuruluyor..."
        ( cd "$ROOT/frontend" && npm ci --offline --no-audit --no-fund ) >"$RUN/frontend-install.log" 2>&1 \
            || fail "Yönetim arayüzünün bağımlılıkları kurulamadı (adım 4). İnternet bağlantısıyla bir kez 'cd frontend && npm ci' çalıştırıp yeniden deneyin." "$RUN/frontend-install.log"
    fi
    say "4/6 Yönetim arayüzü başlatılıyor..."
    ports_free "Yönetim arayüzü" "5173"
    start frontend "$ROOT/frontend" "$RUN/frontend.log" node "$ROOT/frontend/node_modules/vite/bin/vite.js"
fi
wait_http frontend "Yönetim arayüzü (adım 4)" "http://$HOST:5173/" 90 "$RUN/frontend.log"

# 5. Fake AI provider on a free port.
MOCK_STARTED=0
if alive mock_ai && [ -f "$RUN/mock_ai.port" ]; then
    say "5/6 Sahte yapay zekâ sağlayıcısı zaten çalışıyor."
else
    say "5/6 Sahte yapay zekâ sağlayıcısı başlatılıyor..."
    if alive mock_ai; then kill "$(cat "$RUN/mock_ai.pid")" 2>/dev/null; fi
    rm -f "$RUN/mock_ai.port"
    start mock_ai "$ROOT" "$RUN/mock_ai.log" python3 "$ROOT/tools/trial/mock_ai.py" --port 0 --port-file "$RUN/mock_ai.port"
    MOCK_STARTED=1
    waited=0
    while [ ! -s "$RUN/mock_ai.port" ] && [ "$waited" -lt 20 ]; do
        alive mock_ai || fail "Sahte sağlayıcı beklenmedik şekilde kapandı (adım 5)." "$RUN/mock_ai.log"
        sleep 1
        waited=$((waited + 1))
    done
    [ -s "$RUN/mock_ai.port" ] || fail "Sahte sağlayıcı 20 saniye içinde port bildirmedi (adım 5)." "$RUN/mock_ai.log"
fi
MOCK_PORT="$(cat "$RUN/mock_ai.port")"
wait_http mock_ai "Sahte sağlayıcı (adım 5)" "http://$HOST:$MOCK_PORT/healthz" 20 "$RUN/mock_ai.log"

# 6. Trial chat page; restarted when the provider got a new port.
if alive trial_proxy && [ "$MOCK_STARTED" = "1" ]; then
    kill "$(cat "$RUN/trial_proxy.pid")" 2>/dev/null
    sleep 1
fi
if alive trial_proxy; then
    say "6/6 Deneme sohbet sayfası zaten çalışıyor."
else
    say "6/6 Deneme sohbet sayfası başlatılıyor..."
    ports_free "Deneme sohbet sayfası" "8765"
    start trial_proxy "$ROOT" "$RUN/trial_proxy.log" python3 "$ROOT/tools/trial/trial_proxy.py" \
        --port 8765 --icap-port 1344 --mock-port "$MOCK_PORT"
fi
wait_http trial_proxy "Deneme sohbet sayfası (adım 6)" "http://$HOST:8765/healthz" 20 "$RUN/trial_proxy.log"

ADMIN="$(awk '/security_admin \(LDAP\)/ { print $1; exit }' "$DEV/credentials.txt" 2>/dev/null)"
MASKED="$(awk '/replay_viewer \(LDAP/ { print $1; exit }' "$DEV/credentials.txt" 2>/dev/null)"
say ""
say "Deneme hazır."
say "  Sohbet sayfası:    http://$HOST:8765/"
say "  Yönetim arayüzü:   http://$HOST:5173/"
say "  Giriş bilgileri:   java/control/build/dev/credentials.txt (her başlatmada yeniden üretilir)"
say "                     yönetici kullanıcı: ${ADMIN:-synthetic-admin}, maskeli görünüm kullanıcısı: ${MASKED:-synthetic-aiview}"
say "                     parolalar yalnızca bu dosyadadır; ekrana yazdırılmaz."
say "  Günlükler:         tools/trial/.run/"
say "  Adım adım anlatım: tools/trial/DENEME.md"
say "  Durdurmak için:    tools/trial/stop_trial.sh"
