#!/usr/bin/env bash
# Démo live du pipeline, sans compte AWS ni compte LocalStack.
#
# Lance LocalStack en local, applique la configuration Terraform de
# démonstration contre lui, puis affiche les ressources créées — de quoi
# montrer à quelqu'un, en direct, que le pipeline fonctionne réellement,
# sans dépendre de l'onglet Actions de GitHub ni d'un service tiers.
#
# Utilisation :
#   ./scripts/demo-local.sh          # lance la démo (apply)
#   ./scripts/demo-local.sh cleanup  # détruit les ressources et arrête LocalStack

set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"

if [ "${1:-}" = "cleanup" ]; then
  echo "🧹 Nettoyage..."
  (cd terraform/examples && terraform destroy -input=false -auto-approve) || true
  docker compose down
  echo "✅ Terminé — LocalStack arrêté, ressources détruites."
  exit 0
fi

echo "🚀 Démarrage de LocalStack (aucun compte requis, 100% local)..."
docker compose up -d

echo "⏳ Attente que LocalStack soit prêt..."
until curl -sf http://localhost:4566/_localstack/health >/dev/null 2>&1; do
  sleep 2
done
echo "✅ LocalStack prêt."

echo ""
echo "📐 Application de la configuration Terraform (Security Group + instance)..."
cd terraform/examples
terraform init -input=false -upgrade=false
terraform apply -input=false -auto-approve

echo ""
echo "✅ Ressources créées :"
terraform output

if command -v aws >/dev/null 2>&1; then
  echo ""
  echo "🔎 Détail interrogé en direct via l'API EC2 émulée :"
  echo ""
  echo "--- Instance EC2 ---"
  aws --endpoint-url=http://localhost:4566 --region eu-west-3 \
    ec2 describe-instances \
    --instance-ids "$(terraform output -raw instance_id)" \
    --query "Reservations[].Instances[].{Id:InstanceId,Type:InstanceType,State:State.Name,IMDSv2:MetadataOptions.HttpTokens,DiskChiffre:BlockDeviceMappings[0].Ebs.Encrypted}" \
    --output table

  echo "--- Security Group ---"
  aws --endpoint-url=http://localhost:4566 --region eu-west-3 \
    ec2 describe-security-groups \
    --group-ids "$(terraform output -raw security_group_id)" \
    --query "SecurityGroups[].{Id:GroupId,Name:GroupName,Tags:Tags}" \
    --output table
else
  echo ""
  echo "ℹ️  AWS CLI non installée — les sorties Terraform ci-dessus suffisent déjà à"
  echo "   prouver que les ressources existent. Installe 'aws-cli' pour un détail"
  echo "   supplémentaire interrogé en direct."
fi

if command -v conftest >/dev/null 2>&1; then
  echo ""
  echo "🛡️  Contrôle des règles de sécurité (conftest) sur la config EC2 :"
  terraform plan -input=false -out=tfplan.binary >/dev/null
  terraform show -json tfplan.binary > tfplan.json
  conftest test tfplan.json --policy "$ROOT/policies"

  echo ""
  echo "🔑 Partie OIDC : rôles GitHub Actions -> AWS (trust policies)"
  OIDC_DIR="$(mktemp -d)"
  trap 'rm -rf "$OIDC_DIR"' EXIT
  cp "$ROOT/terraform/oidc.tf" "$ROOT/terraform/examples/provider.tf" "$OIDC_DIR/"
  (
    cd "$OIDC_DIR"
    terraform init -input=false >/dev/null
    terraform apply -input=false -auto-approve >/dev/null
    terraform show -json > state.json

    echo ""
    echo "✅ Trust policies conformes (sub strict, aud exact, pas de Principal *) :"
    conftest test state.json --policy "$ROOT/policies" --namespace oidc

    echo ""
    echo "🧪 Simulation de la décision AWS (8 jetons fictifs : PR, main, fork, mauvaise audience...)"
    conftest test state.json --policy "$ROOT/policies" --namespace oidc_sim

    echo ""
    echo "🚨 Refus volontaire : on remplace ':pull_request' par ':*' (le cas du test négatif)"
    sed 's/:pull_request/:*/g' state.json > state_bad.json
    conftest test state_bad.json --policy "$ROOT/policies" --namespace oidc || \
      echo "👉 Refus attendu : une trust policy trop large est bloquée avant d'atteindre AWS."

    echo ""
    echo "🧪 Même state, vu par la simulation : que pourrait assumer un attaquant ?"
    conftest test state_bad.json --policy "$ROOT/policies" --namespace oidc_sim || \
      echo "👉 Avec le joker, un job hors pull_request assumerait le rôle plan."

    terraform destroy -input=false -auto-approve >/dev/null
  )
else
  echo ""
  echo "ℹ️  conftest non installé — le contrôle des règles et la démo OIDC sont ignorés."
fi

echo ""
echo "💡 Pour tout nettoyer ensuite : ./scripts/demo-local.sh cleanup"
