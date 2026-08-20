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

echo ""
echo "💡 Pour tout nettoyer ensuite : ./scripts/demo-local.sh cleanup"
