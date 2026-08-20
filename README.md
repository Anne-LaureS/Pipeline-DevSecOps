# 🛡️ Pipeline DevSecOps de bout en bout

![Terraform](https://img.shields.io/badge/Terraform-1.9.5-844FBA?logo=terraform&logoColor=white)
![OPA](https://img.shields.io/badge/OPA%2FConftest-Policy%20as%20Code-3B82F6?logo=openpolicyagent&logoColor=white)
![LocalStack](https://img.shields.io/badge/LocalStack-AWS%20local-6E56CF?logo=amazonaws&logoColor=white)
![Trivy](https://img.shields.io/badge/Trivy-IaC%20scan-1904DA)
![Gitleaks](https://img.shields.io/badge/Gitleaks-secret%20scan-orange)
![License](https://img.shields.io/badge/licence-usage%20p%C3%A9dagogique-lightgrey)

> 📚 **TP 5 — Module 6 · IaC & Gestion des configurations**

Chaîne de livraison d'infrastructure sécurisée : **aucun secret
permanent**, **contrôles automatiques bloquants**, **séparation
plan/apply**, et démonstration que le pipeline **refuse une
configuration non conforme**.

---

## 🎯 Ce que fait ce pipeline

| Étape | Outil | Rôle |
|---|---|---|
| 🔑 Authentification | OIDC (GitHub ↔ AWS) | Zéro secret statique, jetons temporaires (1h max) |
| 🧹 Qualité | `terraform fmt`, Gitleaks, Trivy | Contrôles bloquants avant tout `plan` |
| 📐 Plan | Terraform + LocalStack | Génère et affiche le plan d'infrastructure |
| 🚦 Policy as Code | Conftest / OPA | Bloque toute ressource non conforme (4 règles) |
| 💬 Revue | Commentaire automatique sur PR | Le plan est visible avant merge |
| ✅ Apply | Environment protégé | Approbation manuelle requise |

---

## 🔐 Conception IAM — pourquoi ce design

Le cœur de ce pipeline n'est pas Terraform, c'est le modèle d'accès qui l'entoure. Détail dans
`terraform/oidc.tf` et partie 1/5 du [rapport](docs/tp5-rapport.md) :

- **Zéro credential permanent** : fédération OIDC GitHub Actions ↔ AWS. Aucune clé d'accès stockée
  en secret GitHub — le job obtient un jeton STS valable 1h maximum, puis rien.
- **Deux rôles, pas un** : `gha-terraform-plan` (lecture seule, 6 actions `Describe*`/`Get*`) et
  `gha-terraform-apply` (écriture) sont des identités IAM distinctes. Une pull request ne peut
  physiquement pas obtenir de droits d'écriture, même si son propre code de workflow était modifié
  dans cette même PR.
- **Confiance scopée par le contenu du jeton, pas juste sa provenance** : la trust policy de chaque
  rôle vérifie le claim `sub` du jeton OIDC — `repo:<ORG>/<REPO>:pull_request` pour `plan`,
  `repo:<ORG>/<REPO>:ref:refs/heads/main` pour `apply`. Résultat : ni un fork, ni une branche
  quelconque, ni un `workflow_dispatch` hors `main` ne peut assumer le rôle d'écriture.
- **Le test négatif fait partie du livrable, pas juste le résultat positif** : la partie 1 du
  rapport documente ce qui se passerait si cette condition `sub` était élargie à `repo:<ORG>/<REPO>:*`
  (n'importe quel contexte du dépôt pourrait assumer le rôle) — scénario d'attaque écrit noir sur
  blanc, pas juste affirmé.
- **Le risque résiduel est assumé, pas caché** : le rôle `apply` utilise encore `resources = ["*"]`
  sur certaines actions faute d'avoir eu le temps de scoper par ARN — documenté explicitement comme
  écart au principe de moindre privilège plutôt que passé sous silence (voir partie 5 du rapport,
  dissertation Saltzer & Schroeder).

---

## 📁 Structure du dépôt

```
.
├── .github/workflows/
│   ├── terraform.yml       # Pipeline principal (qualite → plan → apply)
│   └── oidc-check.yml      # Vérification OIDC minimale
├── terraform/
│   ├── oidc.tf              # Provider OIDC + rôles IAM plan/apply
│   └── examples/            # Ressources de démo testées contre LocalStack
├── policies/
│   └── securite.rego        # 4 règles de sécurité (Conftest/OPA)
├── docs/
│   ├── tp5-rapport.md        # Rapport complet (livrable principal)
│   └── captures/             # Preuves visuelles (commentaire de plan, etc.)
├── .trivyignore              # Risques acceptés, justifiés et tracés
├── docker-compose.yml        # LocalStack pour tester en local
└── .gitignore
```

---

## 🚀 Tester en local

```bash
# 1. Démarrer LocalStack (émulation AWS, gratuit, sans compte réel)
docker compose up -d

# 2. Générer un plan Terraform
cd terraform/examples
terraform init
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > tfplan.json

# 3. Vérifier la conformité des règles de sécurité
conftest test tfplan.json --policy ../../policies
```

Résultat attendu sur la configuration conforme fournie :

```
8 tests, 8 passed, 0 warnings, 0 failures, 0 exceptions
```

---

## 🔒 Les 4 règles de sécurité bloquantes

| # | Règle | Détecte |
|---|---|---|
| 1️⃣ | 🚫 Pas de SSH ouvert | `0.0.0.0/0` sur le port 22 |
| 2️⃣ | 🔐 IMDSv2 obligatoire | `http_tokens != "required"` |
| 3️⃣ | 💾 Chiffrement disque | `encrypted != true` |
| 4️⃣ | 🏷️ Tags obligatoires | `Environment`, `Owner`, `ManagedBy` manquants |

Chacune a été testée **négativement** (violation volontaire → message
de refus capturé) puis **positivement** (retour à la conformité →
`8/8 passed`). Détail complet dans [`docs/tp5-rapport.md`](docs/tp5-rapport.md).

---

## ⚠️ Limite assumée : pas de compte AWS réel

Ce TP a été réalisé sans compte AWS fourni, et sans en créer un à titre personnel et payant. Le pipeline tourne donc contre LocalStack plutôt que contre un vrai compte :

- ✅ Tout ce qui ne dépend pas d'IAM réel (`fmt`, Gitleaks, Trivy,
  `terraform plan`, Conftest) a été testé de bout en bout, sur une
  vraie pull request GitHub.
- ⚠️ La logique OIDC (`terraform/oidc.tf`) est écrite et commentée,
  mais **n'a jamais été exercée en conditions réelles** — LocalStack
  Community n'émule pas l'enforcement IAM.

Ce choix, ses conséquences et les risques résiduels qui en découlent
sont documentés en détail dans la partie 0 et la partie 4 (audit
OWASP Top 10 CI/CD) du [rapport](docs/tp5-rapport.md).

---

## 📄 Livrable principal

👉 **[`docs/tp5-rapport.md`](docs/tp5-rapport.md)** — politique OIDC
commentée, capture du commentaire de plan sur PR, 4 messages de refus
de policy, audit OWASP Top 10 CI/CD complet, et dissertation sur trois
principes de Saltzer & Schroeder.