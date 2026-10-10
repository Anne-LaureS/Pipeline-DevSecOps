#!/usr/bin/env bash
# Test différentiel : OpenBao (second moteur) contre la simulation Rego.
#
# Deux moteurs indépendants évaluent les mêmes jetons contre les mêmes rôles :
#   - policies/oidc_simulation.rego : la simulation de la décision d'AWS ;
#   - OpenBao (fork open source de Vault), méthode d'authentification `jwt` :
#     il vérifie la signature du jeton et compare ses claims à des valeurs liées.
# Les rôles OpenBao sont construits À PARTIR du state Terraform : les valeurs
# testées sont celles de oidc.tf. Un désaccord entre les deux moteurs signale
# un bug dans l'un des deux.
#
# Ce que cela établit : la logique des claims (émetteur, audience, sub) est
# cohérente entre deux implémentations, avec de vrais jetons GitHub en mode
# --github. Ce que cela n'établit PAS : le comportement d'AWS lui-même.
# Limites : OpenBao compare des valeurs exactes (pas la sémantique de StringLike
# d'AWS) ; ni l'un ni l'autre ne modélise les SCP ; ce script n'accepte que des
# conditions StringEquals, seul opérateur dont la liaison exacte est équivalente.
#
# Modes :
#   --local    (défaut) jetons signés par une clé générée localement : les 10
#              scénarios de la simulation (autre dépôt, main, environment...)
#   --github   vrais jetons du job GitHub Actions (permission id-token: write) ;
#              vérification de la signature via le JWKS de GitHub
#
# Utilisation :
#   docker compose --profile openbao up -d openbao
#   scripts/openbao-oidc-check.sh state.json [--local|--github]
# Variables : BAO_ADDR (http://127.0.0.1:8200), BAO_TOKEN (root),
#             EXPECTED_REPO (<org>/<repo>, active la source indépendante du dépôt)

set -euo pipefail

STATE="${1:?usage: $0 <state.json> [--local|--github]}"
MODE="${2:---local}"
BAO_ADDR="${BAO_ADDR:-http://127.0.0.1:8200}"
BAO_TOKEN="${BAO_TOKEN:-root}"
ISSUER="https://token.actions.githubusercontent.com"
AUTH_PATH="gha-${MODE#--}"   # un montage par mode : gha-github / gha-local
HERE="$(cd "$(dirname "$0")" && pwd)"
POLICY_DIR="${POLICY_DIR:-$HERE/../policies}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

for tool in curl python3 conftest; do
  command -v "$tool" >/dev/null 2>&1 || { echo "❌ '$tool' est requis" >&2; exit 1; }
done
[ -f "$STATE" ] || { echo "❌ state introuvable : $STATE" >&2; exit 1; }
case "$MODE" in
  --local) command -v openssl >/dev/null 2>&1 || { echo "❌ 'openssl' est requis pour --local" >&2; exit 1; } ;;
  --github) ;;
  *) echo "❌ mode inconnu : $MODE" >&2; exit 1 ;;
esac

py() { python3 -I -c "$@"; }

api() { # méthode chemin [corps-json]
  local method="$1" path="$2" body="${3:-}"
  if [ -n "$body" ]; then
    curl -sS -X "$method" -H "X-Vault-Token: $BAO_TOKEN" -H "Content-Type: application/json" \
      -d "$body" "$BAO_ADDR/v1/$path"
  else
    curl -sS -X "$method" -H "X-Vault-Token: $BAO_TOKEN" "$BAO_ADDR/v1/$path"
  fi
}

# --- 1. Rôles issus du state : nom -> {sub: [...], aud: [...]} --------------
py '
import json, sys
state = json.load(open(sys.argv[1]))
out = {}
for r in state["values"]["root_module"]["resources"]:
    if r["type"] != "aws_iam_role" or not r["values"]["name"].startswith("gha-terraform-"):
        continue
    doc = json.loads(r["values"]["assume_role_policy"])
    stmts = doc["Statement"] if isinstance(doc["Statement"], list) else [doc["Statement"]]
    subs, auds = [], []
    for st in stmts:
        for op, conds in (st.get("Condition") or {}).items():
            if op != "StringEquals":
                sys.exit(f"opérateur {op} : seul StringEquals est vérifiable par liaison exacte")
            for k, v in conds.items():
                vals = v if isinstance(v, list) else [v]
                if k.endswith(":sub"): subs += vals
                if k.endswith(":aud"): auds += vals
    out[r["values"]["name"]] = {"sub": sorted(set(subs)), "aud": sorted(set(auds))}
json.dump(out, open(sys.argv[2], "w"))
' "$STATE" "$WORK/roles.json"

ROLES="$(py 'import json,sys; print(" ".join(sorted(json.load(open(sys.argv[1])))))' "$WORK/roles.json")"
[ -n "$ROLES" ] || { echo "❌ aucun rôle gha-terraform-* dans le state" >&2; exit 1; }
GOOD_AUD="$(py 'import json,sys; r=json.load(open(sys.argv[1])); print(next(iter(r.values()))["aud"][0])' "$WORK/roles.json")"
BAD_AUD="autre.example.com"

# --- 2. Configuration d'OpenBao ---------------------------------------------
until curl -sf "$BAO_ADDR/v1/sys/health" >/dev/null 2>&1; do sleep 1; done
api POST "sys/auth/$AUTH_PATH" '{"type":"jwt"}' >/dev/null || true

if [ "$MODE" = "--local" ]; then
  openssl genrsa -out "$WORK/key.pem" 2048 2>/dev/null
  openssl rsa -in "$WORK/key.pem" -pubout -out "$WORK/pub.pem" 2>/dev/null
  CFG="$(py 'import json,sys; print(json.dumps({"bound_issuer": sys.argv[1], "jwt_validation_pubkeys": [open(sys.argv[2]).read()]}))' "$ISSUER" "$WORK/pub.pem")"
else
  CFG="$(py 'import json,sys; print(json.dumps({"bound_issuer": sys.argv[1], "oidc_discovery_url": sys.argv[1]}))' "$ISSUER")"
fi
api POST "auth/$AUTH_PATH/config" "$CFG" >/dev/null

for role in $ROLES; do
  BODY="$(py '
import json, sys
r = json.load(open(sys.argv[1]))[sys.argv[2]]
print(json.dumps({
  "role_type": "jwt", "user_claim": "sub",
  "bound_audiences": r["aud"], "bound_claims_type": "string",
  "bound_claims": {"sub": r["sub"]}, "token_policies": ["default"]}))
' "$WORK/roles.json" "$role")"
  api POST "auth/$AUTH_PATH/role/$role" "$BODY" >/dev/null
done

# --- 3. Jetons --------------------------------------------------------------
b64u() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

local_token() { # sub aud
  local h p
  h=$(printf '{"alg":"RS256","typ":"JWT"}' | b64u)
  p=$(printf '{"iss":"%s","sub":"%s","aud":"%s","iat":%d,"exp":%d}' \
      "$ISSUER" "$1" "$2" "$(date +%s)" "$(( $(date +%s) + 600 ))" | b64u)
  printf '%s.%s.%s' "$h" "$p" \
    "$(printf '%s.%s' "$h" "$p" | openssl dgst -sha256 -sign "$WORK/key.pem" | b64u)"
}

github_token() { # aud
  : "${ACTIONS_ID_TOKEN_REQUEST_URL:?exécuter dans un job avec « permissions: id-token: write »}"
  : "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:?jeton de requête OIDC absent}"
  local tok
  tok="$(curl -sSf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
        "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=$(py 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1]))' "$1")" \
        | py 'import json,sys; print(json.load(sys.stdin)["value"])')"
  echo "::add-mask::$tok" >&2
  printf '%s' "$tok"
}

claim() { # jeton claim
  py '
import base64, json, sys
p = sys.argv[1].split(".")[1]
p += "=" * (-len(p) % 4)
print(json.loads(base64.urlsafe_b64decode(p))[sys.argv[2]])
' "$1" "$2"
}

# dossier de données pour conftest (dépôt attendu indépendant + sondes)
mkdir "$WORK/data"
if [ -n "${EXPECTED_REPO:-}" ]; then
  py 'import json,sys; json.dump({"expected_repo": sys.argv[1]}, open(sys.argv[2], "w"))' \
    "$EXPECTED_REPO" "$WORK/data/expected.json"
fi

rego() { # namespace -> JSON conftest sur stdout
  conftest test "$STATE" --policy "$POLICY_DIR" --namespace "$1" --data "$WORK/data" --output json
}

warnings_of() { # lit le JSON conftest, imprime les messages de warn un par ligne
  py '
import json, sys
for res in json.load(sys.stdin):
    for w in res.get("warnings") or []:
        print(w["msg"])
'
}

# paires « sub|aud » à signer, une par ligne
if [ "$MODE" = "--local" ]; then
  # les 10 scénarios de la simulation : les jetons proviennent du moteur Rego lui-même
  echo '{"probes": []}' > "$WORK/data/probes.json"
  PAIRS="$(rego oidc_probe | warnings_of | grep -v '|.*|.*|' | sort -u)"
else
  # vrais jetons : la paire (sub, aud) est lue dans chaque jeton obtenu de GitHub
  PAIRS=""
fi

declare -a TOKENS=() SUBS=() AUDS=()
if [ "$MODE" = "--local" ]; then
  while IFS='|' read -r sub aud; do
    [ -n "$sub" ] || continue
    TOKENS+=("$(local_token "$sub" "$aud")"); SUBS+=("$sub"); AUDS+=("$aud")
  done <<<"$PAIRS"
else
  for aud in "$GOOD_AUD" "$BAD_AUD"; do
    tok="$(github_token "$aud")"
    TOKENS+=("$tok"); SUBS+=("$(claim "$tok" sub)"); AUDS+=("$(claim "$tok" aud)")
  done
fi

# --- 4. Décisions de la simulation pour ces jetons --------------------------
py '
import json, sys
subs, auds = sys.argv[1].split("\n"), sys.argv[2].split("\n")
json.dump({"probes": [{"sub": s, "aud": a} for s, a in zip(subs, auds)]}, open(sys.argv[3], "w"))
' "$(printf '%s\n' "${SUBS[@]}" | sed '$!b')" "$(printf '%s\n' "${AUDS[@]}")" "$WORK/data/probes.json"
rego oidc_probe | warnings_of | grep '|.*|.*|' > "$WORK/sim_decisions.txt" || true

# --- 5. Comparaison ---------------------------------------------------------
FAILED=0
TOTAL=0
echo "🔐 Test différentiel — OpenBao ($BAO_ADDR, mode ${MODE#--}) contre oidc_simulation.rego"
echo "   rôles issus de $(basename "$STATE") : $ROLES"
echo ""
printf '    %-20s %-50s %-18s %-8s %-8s\n' "rôle" "sub" "aud" "Rego" "OpenBao"

for i in "${!TOKENS[@]}"; do
  tok="${TOKENS[$i]}"; sub="${SUBS[$i]}"; aud="${AUDS[$i]}"
  for role in $ROLES; do
    sim="$(grep -F "$role|$sub|$aud|" "$WORK/sim_decisions.txt" | head -1 | awk -F'|' '{print $4}')"
    [ -n "$sim" ] || sim="?"
    case "$sim" in ACCEPTE) sim="ACCEPTÉ" ;; REFUSE) sim="REFUSÉ" ;; esac
    resp="$(api POST "auth/$AUTH_PATH/login" "$(py 'import json,sys; print(json.dumps({"role": sys.argv[1], "jwt": sys.argv[2]}))' "$role" "$tok")")"
    if py 'import json,sys; sys.exit(0 if json.loads(sys.argv[1]).get("auth") else 1)' "$resp"; then
      got="ACCEPTÉ"
    else
      got="REFUSÉ"
    fi
    TOTAL=$((TOTAL + 1))
    mark="✅"
    if [ "$sim" != "$got" ]; then mark="❌"; FAILED=$((FAILED + 1)); fi
    printf '%s  %-20s %-50s %-18s %-8s %-8s\n' "$mark" "$role" "$sub" "$aud" "$sim" "$got"
  done
done

echo ""
if [ "$FAILED" -ne 0 ]; then
  echo "❌ $FAILED désaccord(s) sur $TOTAL comparaisons : un des deux moteurs a un défaut."
  exit 1
fi
echo "✅ $TOTAL comparaisons : OpenBao et la simulation Rego rendent la même décision."
