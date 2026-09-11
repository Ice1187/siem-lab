#!/usr/bin/env bash
#
# APT29 SIEM Lab - one-click setup
#
#   ./setup.sh             build the lab (first run ~10 min, mostly downloading)
#   ./setup.sh --reshift   re-apply the anchor from .env (ANCHOR_DATE/ANCHOR_LOCAL)
#   ./setup.sh --down      stop the containers, keep the data
#   ./setup.sh --clean     stop and delete everything
#
#   --zeek / --no-zeek     load the Zeek network logs, or skip them.
#                          Without either flag you are asked (defaults to yes).
#
# Only requirement: Docker Desktop installed and running.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; B=$'\033[36m'; BD=$'\033[1m'; N=$'\033[0m'
STEP=0
step() { STEP=$((STEP+1)); printf '\n%s[%s/%s] %s%s\n' "$BD$B" "$STEP" "$TOTAL" "$1" "$N"; }
info() { printf '      %s\n' "$1"; }
warn() { printf '%s      ! %s%s\n' "$Y" "$1" "$N"; }
die()  { printf '\n%serror: %s%s\n' "$R" "$1" "$N" >&2; exit 1; }

# Plain, visible config file. Docker Compose only auto-loads ".env", so every
# compose call below passes --env-file explicitly.
CONFIG=lab.conf
dc() { docker compose --env-file "$CONFIG" "$@"; }

MODE=build; ZEEK=ask
for a in "$@"; do case "$a" in
  --reshift) MODE=reshift ;;
  --zeek)    ZEEK=yes ;;
  --no-zeek) ZEEK=no ;;
  --down)    dc down; echo "stopped (data kept)"; exit 0 ;;
  --clean)   dc down -v; rm -f data/shift_delta.json; echo "removed containers and data"; exit 0 ;;
  -h|--help) sed -n '2,15p' "$0" | sed 's/^#\s\{0,1\}//'; exit 0 ;;
  *) die "unknown option: $a" ;;
esac; done
trap 'printf "\n%sFailed at step %s. Fix the error above and run ./setup.sh again (it is safe to re-run).%s\n" "$R" "$STEP" "$N"' ERR

printf '%s\nAPT29 ATT&CK Evals Day 1  ->  Elasticsearch + Kibana lab%s\n' "$BD" "$N"

# Ask everything up front so the rest of the run is unattended.
if [ "$ZEEK" = ask ]; then
  if [ -t 0 ]; then
    printf '\n  Also load the Zeek network logs (2,140 events)?\n'
    printf '  They let students correlate host activity with network traffic.\n'
    printf '  %sLoad Zeek? [Y/n]%s ' "$BD" "$N"
    read -r reply || reply=""
    case "$reply" in [Nn]*) ZEEK=no ;; *) ZEEK=yes ;; esac
  else
    ZEEK=yes   # non-interactive (CI, piped): take the default
  fi
fi
[ "$ZEEK" = yes ] && printf '  -> host events + Zeek network logs\n' \
                  || printf '  -> host events only\n'

TOTAL=7; [ "$MODE" = reshift ] && TOTAL=6
[ "$ZEEK" = no ] && TOTAL=$((TOTAL - 1))

# --------------------------------------------------------------------------- #
step "Checking Docker and tools"
command -v docker >/dev/null 2>&1 || die "Docker not found. Install Docker Desktop, start it, then re-run."
docker info >/dev/null 2>&1     || die "Docker is not running. Start Docker Desktop, then re-run."
docker compose version >/dev/null 2>&1 || die "'docker compose' unavailable. Update Docker Desktop."
command -v git >/dev/null 2>&1  || die "git not found. Install git (macOS: xcode-select --install)."
info "docker $(docker version --format '{{.Server.Version}}')"

MEM_GB=$(( $(docker info --format '{{.MemTotal}}' 2>/dev/null || echo 0) / 1073741824 ))
if [ "$MEM_GB" -lt 6 ]; then
  warn "Docker has ${MEM_GB}GB RAM; Elasticsearch + Kibana want 6GB or more."
  warn "Raise it in Docker Desktop > Settings > Resources > Memory."
else
  info "docker memory ${MEM_GB}GB"
fi

if ! command -v uv >/dev/null 2>&1; then
  info "installing uv (Python runner)..."
  curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null 2>&1 || die "could not install uv"
fi
export PATH="$HOME/.local/bin:$PATH"
command -v uv >/dev/null 2>&1 || die "uv is not on PATH; add \$HOME/.local/bin to PATH and re-run."
info "uv $(uv --version | awk '{print $2}')"
[ -f "$CONFIG" ] || die "$CONFIG not found. It ships with the repo; restore it and re-run."

# Export the settings the Python loaders read. Values are pulled key by key
# rather than by sourcing the file, because some values contain spaces
# (ES_JAVA_OPTS) and sourcing them would execute the second word.
for key in ANCHOR_DATE ANCHOR_LOCAL ANCHOR_TZ ES_URL KIBANA_URL; do
  val=$(grep -E "^[[:space:]]*${key}=" "$CONFIG" 2>/dev/null | tail -1 | cut -d= -f2- \
        | sed -e 's/[[:space:]]*#.*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
              -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'\$/\1/")
  [ -n "$val" ] && export "$key=$val"
done
info "config $CONFIG"

uv sync --quiet
info "python packages ready"

# --------------------------------------------------------------------------- #
# Always run this, including for --reshift: containers may have been stopped,
# removed or lost to a reboot since the last build. The named volumes survive
# that, so bringing them back up keeps the indexed data.
step "Starting Elasticsearch and Kibana"
[ "$MODE" = build ] && dc pull --quiet
dc up -d
printf '      waiting for Elasticsearch'
for _ in $(seq 1 90); do curl -fsS localhost:9200/_cluster/health >/dev/null 2>&1 && break; printf .; sleep 2; done; printf '\n'
curl -fsS localhost:9200/_cluster/health >/dev/null 2>&1 || die "Elasticsearch did not start. See: docker compose --env-file lab.conf logs elasticsearch"
info "elasticsearch up"
printf '      waiting for Kibana (slowest step, up to 3 min)'
for _ in $(seq 1 120); do curl -fsS localhost:5601/api/status 2>/dev/null | grep -q '"level":"available"' && break; printf .; sleep 3; done; printf '\n'
curl -fsS localhost:5601/api/status 2>/dev/null | grep -q '"level":"available"' || die "Kibana did not start. See: docker compose --env-file lab.conf logs kibana"
info "kibana up"

if [ "$MODE" = build ]; then
  step "Downloading the dataset (~600MB, verified byte-for-byte)"
  uv run scripts/fetch_dataset.py
fi

# --------------------------------------------------------------------------- #
step "Loading host events (196,081)"
[ -f data/apt29_evals_day1_manual_2020-05-01225525.json ] \
  || die "dataset not found. Run ./setup.sh (without --reshift) first to download it."
uv run scripts/load_host_events.py

if [ "$ZEEK" = yes ]; then
  step "Loading Zeek network logs (2,140)"
  uv run scripts/load_zeek.py
else
  # Drop a Zeek index left over from an earlier build: after a reshift its
  # timestamps would no longer line up with the host events.
  if curl -fsS -o /dev/null "localhost:9200/winlogbeat-apt29-zeek-day1" 2>/dev/null; then
    curl -fsS -X DELETE "localhost:9200/winlogbeat-apt29-zeek-day1" >/dev/null
    info "removed the Zeek index from a previous build"
  fi
fi

step "Creating the Kibana data view"
curl -fsS -X POST localhost:5601/api/data_views/data_view \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -d '{"data_view":{"id":"apt29-demo","title":"winlogbeat-apt29-*","name":"APT29 lab","timeFieldName":"@timestamp"},"override":true}' \
  >/dev/null && info "data view 'APT29 lab' -> winlogbeat-apt29-*"

step "Verifying"
if [ "$ZEEK" = yes ]; then uv run scripts/verify.py; else uv run scripts/verify.py --no-zeek; fi

LOADED=$([ "$ZEEK" = yes ] && echo 'host events (196,081) + Zeek network logs (2,140)' || echo 'host events (196,081); Zeek skipped - re-run with --zeek to add them')
IFS='|' read -r ANCHOR_DESC ANCHOR_RANGE ANALYZER_URL <<<"$(uv run python - <<'PYEOF'
import json, datetime, zoneinfo
d = json.load(open("data/shift_delta.json"))
tz = zoneinfo.ZoneInfo(d["anchor_tz"])
start = datetime.datetime.fromisoformat(d["anchor_utc"].replace("Z", "+00:00")).astimezone(tz)
end = start + datetime.timedelta(minutes=40)
kind = "fixed date" if d.get("anchor_date_is_fixed") else "follows today"
u0 = start.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
u1 = end.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
tr = (f"timerange=(global:(linkTo:!(timeline),timerange:(from:%27{u0}%27,kind:absolute,to:%27{u1}%27)),"
      f"timeline:(linkTo:!(global),timerange:(from:%27{u0}%27,kind:absolute,to:%27{u1}%27)))")
link = ("http://localhost:5601/app/security/hosts/events?"
        "sourcerer=(default:(id:security-solution-default,selectedPatterns:!(%27winlogbeat-apt29-*%27)))"
        f"&{tr}&query=(language:kuery,query:%27event.category:%22process%22%20and%20event.type:%22start%22%27)")
desc = f'{d["anchor_date"]} {d["anchor_local"]} {d["anchor_tz"]} ({kind})'
rng = f'{start:%b %d, %Y @ %H:%M:%S.000} -> {end:%b %d, %Y @ %H:%M:%S.000}'
print(f"{desc}|{rng}|{link}")
PYEOF
)"
cat <<SUMMARY

${G}${BD}Lab is ready.${N}  Events are replayed at ${BD}${ANCHOR_DESC}${N}

  Kibana     http://localhost:5601
  Discover   http://localhost:5601/app/discover
  Time range set the Kibana time picker to this absolute range:
             ${BD}${ANCHOR_RANGE}${N}
  Analyzer   process creations (open the tree from one of these rows):
             ${ANALYZER_URL}
  Loaded     ${LOADED}

  Stop (keep data)   ./setup.sh --down
  Start again        ./setup.sh
  Re-apply anchor    ./setup.sh --reshift

SUMMARY
