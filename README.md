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
| 🚦 Policy as Code | Conftest / OPA | Bloque toute ressource non conforme (4 règles) et toute trust policy OIDC trop large (5 règles) |
| 💬 Revue | Commentaire automatique sur PR | Le plan est visible avant merge |
| ✅ Apply | Environment protégé | Approbation manuelle requise |

---

## 🔐 Conception IAM — pourquoi ce design

Le cœur de ce pipeline n'est pas Terraform, c'est le modèle d'accès qui l'entoure. Détail dans
`terraform/oidc.tf` et partie 1/5 du [rapport](docs/tp5-rapport.md) :

- **Zéro credential permanent** : fédération OIDC GitHub Actions ↔ AWS. Aucune clé d'accès stockée
  en secret GitHub — le job obtient un jeton STS valable 1h maximum, puis rien.
- **Deux rôles, pas un** : `gha-terraform-plan` (lecture seule, 9 actions `Describe*`/`Get*`) et
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
│   ├── securite.rego        # 4 règles de sécurité sur le plan (Conftest/OPA)
│   ├── oidc.rego            # 5 règles sur les trust policies OIDC (lues dans le state)
│   └── oidc_test.rego       # 11 tests unitaires des règles OIDC (hors ligne)
├── docs/
│   ├── tp5-rapport.md        # Rapport complet (livrable principal)
│   └── captures/             # Preuves visuelles (commentaire de plan, etc.)
├── scripts/
│   └── demo-local.sh         # Démo locale : LocalStack + apply + contrôles policies (option : cleanup)
├── .trivyignore              # Risques acceptés, justifiés et tracés
├── docker-compose.yml        # LocalStack pour tester en local
└── .gitignore
```

---

## 🎥 Démo live (sans compte AWS ni compte LocalStack)

```bash
./scripts/demo-local.sh          # lance LocalStack + apply, affiche les ressources créées
./scripts/demo-local.sh cleanup  # détruit tout et arrête LocalStack
```

![Démarrage de la démo : LocalStack prêt, terraform init](docs/captures/demo-demarrage.png)

La démo enchaîne quatre temps :

1. création du Security Group et de l'instance EC2 sur LocalStack ;
2. contrôle conftest de cette configuration (`8 tests, 8 passed`) ;
3. application de `terraform/oidc.tf` dans un dossier temporaire, puis contrôle des trust
   policies des deux rôles (`6 tests, 6 passed`) ;
4. **refus volontaire** : le `sub` du rôle `plan` est élargi à `:*` dans une copie du state,
   et conftest le bloque (2 violations) — le test négatif décrit dans le rapport, rejoué
   automatiquement.

> ⚠️ Relancer la démo sans `cleanup` échoue : LocalStack n'implémente pas la modification des
> options de metadata d'une instance existante (erreur 501).

Utile pour montrer concrètement à quelqu'un que le pipeline crée de vraies ressources
(Security Group + instance EC2, conformes aux 4 règles de sécurité), sans dépendre de
l'onglet Actions de GitHub ni du Resource Browser LocalStack (qui nécessite un compte).

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

Résultat attendu :

![conftest sur la config EC2 — 8 tests, 8 passed](docs/captures/conftest-ec2-conforme.png)

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

## 🔑 Les 5 règles sur les trust policies OIDC

Les règles de [`policies/oidc.rego`](policies/oidc.rego) vérifient statiquement le contenu de
`terraform/oidc.tf`, sans compte AWS :

| # | Règle | Détecte |
|---|---|---|
| 1️⃣ | 🚫 Pas de joker dans le `sub` | `repo:<ORG>/<REPO>:*` (n'importe quel contexte du dépôt) |
| 2️⃣ | 🎯 Dépôt explicite | `sub` absent, ou `repo:*/<REPO>:...` |
| 3️⃣ | 🔀 Événement attendu par rôle | `plan` ≠ `:pull_request`, ou `apply` ≠ `:ref:refs/heads/main` |
| 4️⃣ | 🎫 Audience exacte | `aud` différent de `sts.amazonaws.com` |
| 5️⃣ | 👤 Pas de `Principal "*"` | trust policy ouverte à toute identité |

**Particularité** : ces règles lisent le **state** (`terraform show -json` après un apply sur
LocalStack) et non le plan. Dans un plan, `assume_role_policy` dépend de l'ARN du provider OIDC,
qui n'existe pas avant l'apply : le champ est « inconnu » et invisible pour conftest.

### Tester hors ligne (sans LocalStack)

```bash
conftest verify --policy policies
```

Résultat attendu :

![conftest verify — 11 tests, 11 passed](docs/captures/oidc-tests-unitaires.png)

### Tester sur un vrai state, avec refus volontaire

```bash
# LocalStack démarré (docker compose up -d)
mkdir /tmp/oidc && cp terraform/oidc.tf terraform/examples/provider.tf /tmp/oidc && cd /tmp/oidc
terraform init
terraform apply -auto-approve
terraform show -json > state.json

# Cas conforme : 6 tests, 6 passed
conftest test state.json --policy <chemin-du-depot>/policies --namespace oidc

# Violation volontaire : sub élargi à ':*' -> 2 violations attendues
sed -i 's/:pull_request/:*/g' state.json
conftest test state.json --policy <chemin-du-depot>/policies --namespace oidc

terraform destroy -auto-approve
```

Résultat attendu sur le cas conforme :

![Trust policies conformes — 6 tests, 6 passed](docs/captures/oidc-state-conforme.png)

Résultat attendu sur la violation volontaire (le dépôt refuse le `sub` élargi) :

![Refus volontaire du sub en ':*' — 2 violations](docs/captures/oidc-refus-joker.png)

---

## ⚠️ Limite assumée : pas de compte AWS réel

Ce TP a été réalisé sans compte AWS fourni, et sans en créer un à titre personnel et payant. Le pipeline tourne donc contre LocalStack plutôt que contre un vrai compte :

- ✅ Tout ce qui ne dépend pas d'IAM réel (`fmt`, Gitleaks, Trivy,
  `terraform plan`, Conftest) a été testé de bout en bout, sur une
  vraie pull request GitHub.
- ⚠️ La logique OIDC (`terraform/oidc.tf`) est écrite et commentée,
  mais **n'a jamais été exercée en conditions réelles** — LocalStack
  Community n'émule pas l'enforcement IAM. Elle est en revanche
  **vérifiée statiquement** : les 5 règles de `policies/oidc.rego`
  contrôlent le contenu des trust policies (voir plus haut). Cela prouve
  que la condition est bien posée, pas qu'AWS l'applique.

Ce choix, ses conséquences et les risques résiduels qui en découlent
sont documentés en détail dans la partie 0 et la partie 4 (audit
OWASP Top 10 CI/CD) du [rapport](docs/tp5-rapport.md).

---

## 📄 Livrable principal

👉 **[`docs/tp5-rapport.md`](docs/tp5-rapport.md)** — politique OIDC
commentée, capture du commentaire de plan sur PR, 4 messages de refus
de policy, audit OWASP Top 10 CI/CD complet, et dissertation sur trois
principes de Saltzer & Schroeder.
