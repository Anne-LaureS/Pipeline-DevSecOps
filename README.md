# 🛡️ Pipeline DevSecOps de bout en bout

![Terraform](https://img.shields.io/badge/Terraform-1.9.5-844FBA?logo=terraform&logoColor=white)
![OPA](https://img.shields.io/badge/OPA%2FConftest-Policy%20as%20Code-3B82F6?logo=openpolicyagent&logoColor=white)
![LocalStack](https://img.shields.io/badge/LocalStack-AWS%20local-6E56CF?logo=amazonaws&logoColor=white)
![Trivy](https://img.shields.io/badge/Trivy-IaC%20scan-1904DA)
![Gitleaks](https://img.shields.io/badge/Gitleaks-secret%20scan-orange)

> 🛠️ **Projet — IaC, IAM & Policy as Code**

## 🧭 En 2 minutes

**Le sujet.** Comment un pipeline GitHub Actions peut-il déployer de l'infrastructure sur AWS
**sans qu'aucune clé d'accès ne soit stockée** nulle part, et comment s'assurer, automatiquement,
qu'une configuration dangereuse est refusée avant d'arriver en production ?

**La réponse de ce dépôt.**

1. **Pas de secret permanent** : GitHub prouve son identité à AWS avec un jeton temporaire (OIDC).
2. **Deux identités AWS distinctes** : l'une ne peut que *lire* (pour le `plan`), l'autre peut
   *écrire* (pour le `apply`) et n'est accessible qu'à un job passant par l'environment protégé
   `production`.
3. **Des règles écrites en code** (*policy as code*) qui bloquent une configuration non conforme,
   y compris une identité trop permissive.

**Ce qui est réel et ce qui ne l'est pas.** Il n'y a pas de compte AWS derrière ce projet : tout
tourne contre **LocalStack**, un AWS émulé en local. LocalStack n'applique pas les conditions de
sécurité IAM (il accepte n'importe quel jeton, voir plus bas). La configuration OIDC est donc
**écrite, vérifiée statiquement et simulée, mais jamais exercée sur un vrai AWS**.

| | Statut |
|---|---|
| `fmt`, Gitleaks, Trivy, `terraform plan`, règles EC2 | ✅ testés de bout en bout, sur une vraie pull request |
| Règles sur les trust policies OIDC | ✅ vérifiées sur le state, tests unitaires, CI |
| Décision d'AWS (qui peut assumer quel rôle) | 🟡 **simulée**, pas observée |
| `AssumeRoleWithWebIdentity` réel | ❌ jamais exercé (pas de compte AWS) |

---

## 📑 Sommaire

1. [Glossaire](#-glossaire)
2. [Prérequis](#-prérequis)
3. [Ce que fait ce pipeline](#-ce-que-fait-ce-pipeline)
4. [Conception IAM](#-conception-iam--pourquoi-ce-design)
5. [Structure du dépôt](#-structure-du-dépôt)
6. [Démo live](#-démo-live-sans-compte-aws)
7. [Tester pas à pas](#-tester-pas-à-pas)
8. [Les règles de sécurité EC2](#-les-4-règles-de-sécurité-sur-le-plan)
9. [Les règles sur les trust policies OIDC](#-les-5-règles-sur-les-trust-policies-oidc)
10. [Ce que LocalStack n'applique pas, et la simulation](#-ce-que-localstack-napplique-pas--et-la-simulation)
11. [Limites et risques assumés](#️-limites-et-risques-assumés)

---

## 📖 Glossaire

| Terme | En clair |
|---|---|
| **OIDC** | Protocole par lequel GitHub délivre à un job un **jeton signé** qui prouve « je suis tel dépôt, déclenché par tel événement ». AWS peut le vérifier sans qu'aucun secret n'ait été partagé à l'avance. |
| **Rôle IAM** | Une identité AWS portant des permissions. On ne se connecte pas *en tant que* rôle : on l'**assume** temporairement. |
| **Trust policy** | La règle attachée à un rôle qui dit **qui a le droit de l'assumer**. C'est elle qui décide si un jeton OIDC est accepté. |
| **Claim `sub`** | Le champ du jeton qui dit *qui* demande : dépôt + contexte, ex. `repo:ORG/REPO:pull_request`. La trust policy le compare à un motif. |
| **Claim `aud`** | L'audience du jeton : à qui il est destiné (`sts.amazonaws.com`). |
| **`plan` / `apply`** | `terraform plan` montre ce qui va changer (lecture) ; `terraform apply` le fait (écriture). |
| **State** | Le fichier où Terraform note ce qu'il a réellement créé. |
| **Policy as code (Rego / OPA / Conftest)** | Des règles de conformité écrites en code (Rego), évaluées par OPA via l'outil Conftest, qui refusent une configuration fautive. |
| **LocalStack** | Un émulateur local de l'API AWS (via Docker). Gratuit, sans compte, mais il n'applique pas les contrôles de sécurité IAM. |

---

## 🧰 Prérequis

| Outil | Rôle | Vérifier |
|---|---|---|
| Docker (avec Compose) | Lancer LocalStack | `docker --version` |
| Terraform ≥ 1.9 | Plan / apply | `terraform version` |
| Conftest ≥ 0.55 | Évaluer les règles Rego | `conftest --version` |
| `aws` CLI *(facultatif)* | Détail de la démo, reproduction du constat LocalStack | `aws --version` |

> 💡 Si `terraform` est installé via **snap** et que le shell répond « command not found » :
> `export PATH="$PATH:/snap/bin"`.

Aucun compte AWS ni compte LocalStack n'est nécessaire.

---

## 🎯 Ce que fait ce pipeline

| Étape | Outil | Rôle |
|---|---|---|
| 🧹 Qualité | `terraform fmt`, Gitleaks, Trivy | Contrôles bloquants avant tout `plan` |
| 📐 Plan | Terraform + LocalStack | Génère et affiche le plan d'infrastructure |
| 🚦 Policy as Code | Conftest / OPA | Bloque toute ressource non conforme (4 règles) et toute trust policy OIDC trop large (5 règles + simulation) |
| 💬 Revue | Commentaire automatique sur PR | Le plan est visible avant merge |
| ✅ Apply | Environment `production` | Approbation manuelle selon la configuration de l'environment |
| 🔑 Authentification | OIDC GitHub ↔ AWS | Conçue et vérifiée statiquement ; **non exercée** (pas de compte AWS), le CI utilise LocalStack |

Résultat sur une pull request réelle (règles EC2, règles OIDC et simulation incluses) :

![Checks GitHub verts sur la PR : qualite et plan réussis, apply ignoré](docs/captures/ci-pr-checks-verts.png)

---

## 🔐 Conception IAM — pourquoi ce design

Le cœur de ce pipeline n'est pas Terraform, c'est le modèle d'accès qui l'entoure. Détail dans
[`terraform/oidc.tf`](terraform/oidc.tf) et dans le [rapport](docs/rapport.md) :

- **Zéro credential permanent** : fédération OIDC GitHub Actions ↔ AWS. Aucune clé d'accès stockée
  en secret GitHub — le job obtient des credentials STS valables 1 h maximum (`max_session_duration`).
- **Deux rôles, pas un** : `gha-terraform-plan` (lecture) et `gha-terraform-apply` (écriture) sont
  des identités IAM distinctes. Un job déclenché par une pull request reçoit un jeton dont le `sub`
  est `…:pull_request` : la trust policy du rôle d'écriture ne l'accepte pas, même si le workflow
  est modifié dans cette PR.
- **Confiance scopée par le contenu du jeton, pas seulement sa provenance** : la trust policy
  vérifie le claim `sub` :

  | Rôle | `sub` accepté | Pourquoi |
  |---|---|---|
  | `gha-terraform-plan` | `repo:<ORG>/<REPO>:pull_request` | une PR de ce dépôt, lecture seule |
  | `gha-terraform-apply` | `repo:<ORG>/<REPO>:environment:production` | un job de ce dépôt déclarant `environment: production` |

- **Pourquoi l'environment pour `apply` et non la branche `main`** : dès qu'un job déclare
  `environment:`, GitHub remplace le `sub` par `…:environment:<nom>` (le ref n'y figure plus). Une
  condition sur `ref:refs/heads/main` aurait donc **refusé** le job `apply`. Cette erreur de
  conception avait été écrite initialement ; elle est corrigée et couverte par un test de
  régression. En contrepartie, l'environment doit être configuré côté GitHub (*Settings →
  Environments → production*) avec des **reviewers obligatoires** et des **Deployment branches
  limitées à `main`** : sans cela, n'importe quelle branche pourrait cibler cet environment.
- **Le test négatif fait partie de la démarche** : le [rapport](docs/rapport.md) documente ce qui se
  passerait si la condition `sub` était élargie à `repo:<ORG>/<REPO>:*` (n'importe quel contexte du
  dépôt pourrait assumer le rôle) ; ce scénario est désormais rejoué automatiquement par les règles
  et la simulation.
- **Les risques résiduels sont assumés** (détail dans [Limites](#️-limites-et-risques-assumés)) :
  `resources = ["*"]` sur le rôle `apply`, et `s3:Get*` sur `*` côté `plan`.

---

## 📁 Structure du dépôt

```
.
├── .github/workflows/
│   ├── terraform.yml        # Pipeline principal (qualité → plan → apply)
│   └── oidc-check.yml       # Contrôle OIDC sur un VRAI compte AWS (déclenchement manuel)
├── terraform/
│   ├── oidc.tf              # Provider OIDC + rôles IAM plan/apply
│   └── examples/            # Ressources de démo testées contre LocalStack
├── policies/
│   ├── securite.rego        # 4 règles de sécurité sur le plan (Conftest/OPA)
│   ├── oidc.rego            # 5 règles sur les trust policies (lues dans le state)
│   ├── oidc_test.rego       # 12 tests unitaires de ces règles (hors ligne)
│   ├── oidc_simulation.rego # simulation de la décision AssumeRoleWithWebIdentity (10 jetons)
│   └── oidc_simulation_test.rego  # 24 tests du moteur de simulation
├── docs/
│   ├── rapport.md       # Rapport détaillé
│   ├── oidc-architecture.svg
│   └── captures/            # Preuves visuelles
├── scripts/
│   └── demo-local.sh        # Démo locale : LocalStack + apply + contrôles (option : cleanup)
├── .trivyignore             # Risques acceptés, justifiés et tracés
├── docker-compose.yml       # LocalStack pour tester en local
└── .gitignore
```

---

## 🎥 Démo live (sans compte AWS)

```bash
./scripts/demo-local.sh          # lance LocalStack + apply + contrôles
./scripts/demo-local.sh cleanup  # détruit tout et arrête LocalStack
```

![Démarrage de la démo : LocalStack prêt, terraform init](docs/captures/demo-demarrage.png)

La démo enchaîne :

1. création d'un Security Group et d'une instance EC2 sur LocalStack ;
2. contrôle Conftest de cette configuration (règles EC2) ;
3. application de `terraform/oidc.tf` dans un dossier temporaire, puis contrôle des trust policies
   des deux rôles ;
4. **simulation** de la décision d'AWS sur 10 jetons fictifs ;
5. **refus volontaire** : le `sub` du rôle `plan` est élargi à `:*` dans une copie du state, les
   règles le bloquent et la simulation montre qu'un push sur `main` assumerait ce rôle.

> ⚠️ Relancer la démo sans `cleanup` échoue : LocalStack n'implémente pas la modification des
> options de metadata d'une instance existante (erreur 501).

---

## 🚀 Tester pas à pas

Tout se lance depuis la racine du dépôt.

### 1. Règles unitaires, hors ligne (rien à démarrer)

```bash
conftest verify --policy policies
```

Résultat attendu : `0 failures` (36 tests au total).

![conftest verify — tests unitaires des règles OIDC](docs/captures/oidc-tests-unitaires.png)

### 2. Règles EC2 sur un plan

```bash
docker compose up -d                       # LocalStack
cd terraform/examples
terraform init
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > tfplan.json
conftest test tfplan.json --policy ../../policies
cd ../..
```

Résultat attendu :

![conftest sur la config EC2 — 8 tests, 8 passed](docs/captures/conftest-ec2-conforme.png)

### 3. Trust policies OIDC sur un state, avec refus volontaire

```bash
REPO="$(pwd)"                               # racine du dépôt
WORK="$(mktemp -d)"
cp terraform/oidc.tf terraform/examples/provider.tf "$WORK/" && cd "$WORK"
terraform init && terraform apply -auto-approve
terraform show -json > state.json

# Cas conforme
conftest test state.json --policy "$REPO/policies" --namespace oidc
conftest test state.json --policy "$REPO/policies" --namespace oidc_sim

# Violation volontaire : sub élargi à ':*'
sed 's/:pull_request/:*/g' state.json > bad.json
conftest test bad.json --policy "$REPO/policies" --namespace oidc       # 2 violations
conftest test bad.json --policy "$REPO/policies" --namespace oidc_sim   # 1 violation

terraform destroy -auto-approve && cd "$REPO" && docker compose down
```

Résultat attendu sur le cas conforme :

![Trust policies conformes — 6 tests, 6 passed](docs/captures/oidc-state-conforme.png)

Résultat attendu sur la violation volontaire :

![Refus volontaire du sub en ':*' — 2 violations](docs/captures/oidc-refus-joker.png)

---

## 🔒 Les 4 règles de sécurité sur le plan

| # | Règle | Détecte |
|---|---|---|
| 1️⃣ | 🚫 Pas de SSH ouvert | `0.0.0.0/0` sur le port 22 |
| 2️⃣ | 🔐 IMDSv2 obligatoire | `http_tokens != "required"` |
| 3️⃣ | 💾 Chiffrement disque | `encrypted != true` |
| 4️⃣ | 🏷️ Tags obligatoires | `Environment`, `Owner`, `ManagedBy` manquants |

Chacune a été testée **négativement** (violation volontaire → message de refus capturé) puis
**positivement** (retour à la conformité → `8/8 passed`). Détail dans le
[rapport](docs/rapport.md).

---

## 🔑 Les 5 règles sur les trust policies OIDC

[`policies/oidc.rego`](policies/oidc.rego) vérifie le **contenu** des trust policies, sans compte
AWS :

| # | Règle | Détecte |
|---|---|---|
| 1️⃣ | 🚫 Pas de joker dans le `sub` | `repo:<ORG>/<REPO>:*` (n'importe quel contexte du dépôt) |
| 2️⃣ | 🎯 Dépôt explicite | `sub` absent, ou `repo:*/<REPO>:...` |
| 3️⃣ | 🔀 Contexte attendu par rôle | `plan` ≠ `:pull_request`, ou `apply` ≠ `:environment:production` |
| 4️⃣ | 🎫 Audience exacte | `aud` différent de `sts.amazonaws.com` |
| 5️⃣ | 👤 Pas de `Principal "*"` | trust policy ouverte à toute identité |

**Particularité** : ces règles lisent le **state** (`terraform show -json` après un apply sur
LocalStack) et non le plan. Dans un plan, `assume_role_policy` dépend de l'ARN du provider OIDC, qui
n'existe pas avant l'apply : le champ est « inconnu » et invisible pour Conftest.

---

## 🧪 Ce que LocalStack n'applique pas — et la simulation

**Constat.** On pourrait croire que LocalStack permet de « faire marcher » l'OIDC sans compte AWS.
Ce n'est pas le cas : il renvoie des credentials pour **n'importe quel jeton**, sans vérifier la
signature ni les conditions `sub` / `aud`. Test réalisé sur les rôles de `oidc.tf` appliqués à
LocalStack 4.4.0 (jetons fictifs non signés) :

| Jeton | Décision d'AWS | LocalStack |
|---|---|---|
| PR du bon dépôt → rôle `plan` | accepté | accepté |
| **PR d'un autre dépôt** → rôle `plan` | **refusé** | **accepté** ❌ |
| **PR du bon dépôt** → rôle `apply` | **refusé** | **accepté** ❌ |

Un `AssumeRole` réussi sur LocalStack ne prouve donc rien sur la sécurité du design.

<details>
<summary>Reproduire le constat</summary>

```bash
# LocalStack démarré et oidc.tf appliqué (étape 3 ci-dessus)
b64() { printf '%s' "$1" | base64 -w0 | tr '+/' '-_' | tr -d '='; }
jwt() { echo "$(b64 '{"alg":"none","typ":"JWT"}').$(b64 "$1").c2ln"; }
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=eu-west-3
aws --endpoint-url=http://localhost:4566 sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::000000000000:role/gha-terraform-plan \
  --role-session-name test-session \
  --web-identity-token "$(jwt '{"aud":"sts.amazonaws.com","sub":"repo:attaquant/evil:pull_request"}')"
# -> credentials renvoyés, alors qu'AWS refuserait
```
</details>

**La simulation.** Faute de pouvoir interroger AWS,
[`policies/oidc_simulation.rego`](policies/oidc_simulation.rego) rejoue l'évaluation documentée
d'AWS sur 10 jetons fictifs et vérifie que chaque rôle les accepte ou les refuse comme prévu :

| Jeton fictif | Rôle | Attendu |
|---|---|---|
| PR du dépôt | `plan` | accepté |
| Job du dépôt sur l'environment `production` | `apply` | accepté |
| PR du dépôt | `apply` | refusé |
| Push sur `main` du dépôt | `plan` | refusé |
| Push sur `main` **sans** environment | `apply` | refusé |
| Job du dépôt sur un autre environment | `apply` | refusé |
| Push sur une branche quelconque | `apply` | refusé |
| PR d'un fork (autre organisation) | `plan` | refusé |
| Environment `production` d'un fork | `apply` | refusé |
| PR du dépôt, mauvaise audience | `plan` | refusé |

```bash
conftest test state.json --policy policies --namespace oidc_sim
```

Moteur modélisé : statements `Allow` et `Deny` (un `Deny` explicite l'emporte), opérateurs
`StringEquals`, `StringEqualsIgnoreCase`, `StringLike`, `StringNotEquals`, `StringNotLike`, ET entre
les conditions, OU entre les valeurs d'une clé, clé absente = faux pour un opérateur positif et vrai
pour un négatif.

Les règles de la section précédente contrôlent la *forme* des policies ; la simulation contrôle leur
*effet*. Sur le state avec `sub` en `:*`, elle signale qu'un push sur `main` assumerait le rôle
`plan`.

> ⚠️ **C'est une simulation, pas AWS.** Tout opérateur non modélisé (`ForAnyValue:`, `IfExists`,
> `Bool`...) est **signalé** (« simulation non concluante ») plutôt qu'ignoré. Les SCP et
> permission boundaries ne sont pas modélisés ; la signature du jeton et le thumbprint ne sont pas
> vérifiés.

---

## ⚠️ Limites et risques assumés

**Pas de compte AWS réel.** Ce projet est réalisé sans compte AWS : je n'en ai pas créé, pour éviter
tout coût.

- ✅ `fmt`, Gitleaks, Trivy, `terraform plan`, Conftest : testés de bout en bout sur une vraie pull
  request GitHub.
- ⚠️ La logique OIDC n'a **jamais été exercée en conditions réelles**. Elle est vérifiée
  statiquement et simulée : cela prouve que les conditions sont bien posées, pas qu'AWS les applique.
- ⚠️ Le CI n'utilise pas l'OIDC : le job `plan` tourne contre LocalStack. Le workflow
  [`oidc-check.yml`](.github/workflows/oidc-check.yml), à lancer à la main, est prévu pour un vrai
  compte (il échoue tant que `ACCOUNT_ID` n'est pas renseigné).

**Risques résiduels de moindre privilège** (écarts connus, non corrigés faute de temps) :

- Le rôle `apply` utilise `resources = ["*"]` (ex. `ec2:*`, `s3:*`) : à scoper par ARN ou par tag.
- Le rôle `plan` est « lecture seule » mais `s3:Get*` sur `*` permet de **lire le contenu de tous
  les objets** de tous les buckets : à restreindre à `s3:GetBucket*` et aux seuls buckets utiles.
- Les variables `github_org` / `github_repo` valent encore `VOTRE_ORG` / `VOTRE_REPO` : à renseigner
  avant tout vrai déploiement.

Ces choix et les risques qui en découlent sont détaillés dans les parties 0 et 4 (audit OWASP Top 10
CI/CD) du [rapport](docs/rapport.md).

---

## 📄 Rapport détaillé

👉 **[`docs/rapport.md`](docs/rapport.md)** — politique OIDC commentée, capture du
commentaire de plan sur PR, 4 messages de refus de policy, vérification automatisée des trust
policies, audit OWASP Top 10 CI/CD complet, et dissertation sur trois principes de Saltzer &
Schroeder.
