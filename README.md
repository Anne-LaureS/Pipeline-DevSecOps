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