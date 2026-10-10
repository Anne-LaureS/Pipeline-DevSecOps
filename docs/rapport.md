# 🛡️ Pipeline DevSecOps de bout en bout — Rapport

<a id="glossaire"></a>
## 📖 Glossaire

Les termes utilisés dans ce rapport et dans le [README](../README.md).

| Terme | En clair |
|---|---|
| **OIDC (OpenID Connect)** | **Protocole d'authentification**, couche d'identité construite sur OAuth 2.0 : un **fournisseur d'identité** émet des **jetons signés** (JWT) décrivant une identité, que d'autres services (les *relying parties*) acceptent ou refusent. Ici, GitHub est le fournisseur d'identité et AWS la *relying party*. |
| **Fédération GitHub → AWS** | Un job demande à GitHub un jeton décrivant ce job (dépôt, branche, événement, environment…) — il lui faut la permission `id-token: write` — puis l'échange auprès d'**AWS STS** (`AssumeRoleWithWebIdentity`) contre des credentials temporaires. AWS vérifie la signature avec les clés publiques publiées par GitHub, puis applique la trust policy du rôle. La confiance est posée **à l'avance**, en déclarant GitHub comme fournisseur OIDC dans IAM ; aucune clé d'accès n'est échangée. |
| **Jeton (JWT) et claims** | Le jeton est un document signé dont les champs, les *claims*, portent l'émetteur (`iss`), l'audience (`aud`), le sujet (`sub`) et une expiration courte. |
| **Rôle IAM** | Identité AWS **sans identifiants permanents**, définie par deux éléments : une *trust policy* (qui peut l'assumer) et des *policies de permissions* (ce qu'elle peut faire). Une identité autorisée l'**assume** via AWS STS et reçoit des credentials temporaires (clé d'accès, secret, session token) limités aux permissions du rôle, y compris une identité fédérée comme un job GitHub, qui n'a aucun compte IAM. |
| **Trust policy** | La policy attachée à un rôle qui dit **qui peut l'assumer**, sous quelles conditions sur les claims du jeton. Elle ne donne **aucune permission** : celles-ci viennent des autres policies du rôle. |
| **Claim `sub`** | Le claim qui dit *qui* demande : dépôt + contexte, ex. `repo:ORG/REPO:pull_request`. Les conditions de la trust policy (`StringEquals`, `StringLike`) le comparent à un motif. |
| **Claim `aud`** | L'audience visée par le jeton. Pour AWS STS, elle doit valoir `sts.amazonaws.com`. |
| **`plan` / `apply`** | `terraform plan` montre ce qui va changer (lecture) ; `terraform apply` le fait (écriture). |
| **State** | Le fichier où Terraform note ce qu'il a réellement créé. |
| **Policy as code (Rego / OPA / Conftest)** | Des règles de conformité écrites en code (Rego), évaluées par OPA via l'outil Conftest, qui refusent une configuration fautive. |
| **OpenBao** | Fork open source de HashiCorp Vault. Sa méthode d'authentification `jwt` vérifie la signature d'un jeton OIDC et compare ses claims à des valeurs liées : ici, un second moteur indépendant pour recouper la simulation. |
| **Sub immuable** | Forme du claim `sub` que GitHub émet pour les dépôts qui l'activent : `repo:ORG@<id>/REPO@<id>:...`, avec les identifiants numériques du propriétaire et du dépôt, insensibles au renommage. |
| **LocalStack** | Un émulateur local de l'API AWS (via Docker). Gratuit, sans compte, mais il n'applique pas les contrôles de sécurité IAM. |

---

<a id="partie-0"></a>
## 📝 0. Note méthodologique — pourquoi LocalStack

Ce projet n'utilise pas de compte AWS : je n'ai pas voulu en créer un
personnel et payant. J'ai donc fait tourner la partie
"infrastructure exécutable" du pipeline (`terraform plan`/`apply`,
`conftest`) contre **LocalStack** 🐳 (émulation locale de l'API AWS
via Docker, gratuite, sans donnée réelle), plutôt que contre un vrai
compte. Conséquences assumées, à lire en regard de la partie 4 :

- ⚠️ Le provider OIDC GitHub → AWS et les deux rôles IAM
  (`terraform/oidc.tf`) sont écrits, commentés et corrects du point de
  vue du code, mais **n'ont jamais été appliqués ni exercés en
  conditions réelles** : je n'ai pas de preuve d'exécution que
  `AssumeRoleWithWebIdentity` fonctionne, ni que la condition `sub`
  bloque effectivement un contexte non autorisé sur un vrai compte.
- ⚠️ LocalStack Community n'émule pas l'application réelle des
  politiques IAM (permissions "à blanc" au niveau du moteur), donc le
  test négatif de la partie 1 (élargir `sub` à `repo:*` et constater
  l'impact) a été traité comme une analyse écrite plutôt que comme une
  démonstration live. Il est depuis complété par un contrôle **statique**
  automatisé (voir la partie 1, « Vérification automatisée ») : cela
  prouve que la condition est correctement posée, pas qu'AWS l'applique.
- ✅ En revanche, tout ce qui ne dépend pas d'IAM réel — `terraform
  fmt`, `gitleaks`, `trivy config`, le `terraform plan` généré, et
  surtout **`conftest` qui bloque bien sur les 4 règles de policy** —
  a été testé de bout en bout, PR réelle à l'appui.

---

<a id="partie-1"></a>
## 🔐 1. Politique de confiance OIDC finale (commentée)

Voir `terraform/oidc.tf`. Extrait de la condition finale, rôle apply. Le `sub` est comparé en
`StringEquals` (valeur exacte) et non en `StringLike`, parce qu'aucun joker n'est voulu : avec
`StringLike`, un `*` ajouté plus tard élargirait la confiance en silence ; avec `StringEquals`, il
resterait un caractère littéral. Le test négatif ci-dessous bascule donc l'opérateur **et** ajoute le
`*`, ce qui reproduit le risque réel d'une modification malencontreuse.

```hcl
condition {
  test     = "StringEquals"
  variable = "token.actions.githubusercontent.com:sub"
  # Restreint strictement l'assomption du rôle aux jobs de CE dépôt
  # qui déclarent `environment: production`. Empêche toute PR, fork ou
  # branche d'obtenir des droits d'écriture. NB : un job qui déclare un
  # environment reçoit sub=...:environment:<nom> et non ...:ref:...,
  # d'où cette condition (voir « Évolution de conception » ci-dessous).
  values   = ["repo:<ORG>/<REPO>:environment:production"]
}
```

Rôle plan, lecture seule, restreint aux événements `pull_request` :

```hcl
values = ["repo:<ORG>/<REPO>:pull_request"]
```

<figure>
  <img src="oidc-architecture.svg" alt="Schéma : une pull request obtient un jeton OIDC avec sub=pull_request et ne peut assumer que le rôle de lecture ; un job de l'environment production obtient sub=environment:production et peut seul assumer le rôle d'écriture. Le chemin PR vers le rôle d'écriture est explicitement refusé (sub ne correspond pas)." width="100%" />
  <figcaption><i>Deux contextes GitHub, deux conditions <code>sub</code> distinctes, deux rôles isolés — une PR ne peut
  physiquement pas atteindre le rôle d'écriture, condition vérifiée par AWS lui-même à l'<code>AssumeRole</code>.</i></figcaption>
</figure>

### 🧪 Test négatif

**Condition testée :** `repo:<ORG>/<REPO>:*`

**💥 Ce qu'un attaquant pourrait faire avec cette condition élargie :**
- Toute personne pouvant déclencher un run sur le dépôt — y compris via
  un `workflow_dispatch` sur une branche non protégée, ou un push sur
  n'importe quelle branche — pourrait assumer le rôle, y compris le
  rôle d'écriture s'il partageait cette même condition large.
- Un contributeur externe capable d'ouvrir une PR modifiant un workflow
  (si les workflows ne sont pas protégés par CODEOWNERS) pourrait
  injecter un step exécutant `aws sts get-caller-identity` puis
  exfiltrer les credentials temporaires vers un service tiers.
- Combiné à un rôle trop permissif (ex : `apply` avec `iam:PassRole` ou
  `iam:*`), cela ouvre une voie d'escalade de privilèges complète :
  création de nouvelles identités, modification de politiques,
  persistance dans le compte AWS.
- Le caractère temporaire du jeton (max 1h ici) limite la fenêtre
  d'exploitation mais ne l'annule pas : 1h suffit pour créer une
  porte dérobée (utilisateur IAM avec clé d'accès longue durée, par
  exemple), qui elle sera permanente.

**✅ Remédiation appliquée :** condition restaurée à `pull_request` /
`environment:production` (cf. fichier Terraform final), + protection de
la branche `main` (ruleset `protect-main` : pull request obligatoire,
checks `qualite` et `plan` requis, branche à jour avant merge) et
environment `production` limité à `main` avec reviewer obligatoire,
empêchant qu'un changement de workflow atteigne `main` sans passer par
une PR et ses contrôles, ni se déployer sans approbation. **Limite
assumée** : le ruleset n'exige aucune approbation de PR (dépôt à un
seul mainteneur, qui ne peut pas approuver sa propre PR) ; la garantie
repose donc sur les checks automatiques et sur l'approbation du
déploiement, pas sur la relecture d'un tiers.

<a id="evolution-sub-apply"></a>
### 🔄 Évolution de conception : le `sub` du rôle apply

La première version de la condition du rôle `apply` visait
`repo:<ORG>/<REPO>:ref:refs/heads/main`. Or le job `apply` du workflow
déclare `environment: production` : GitHub place alors
`repo:<ORG>/<REPO>:environment:production` dans le claim `sub` (le ref
n'y figure plus). Sur un vrai compte, AWS aurait donc **refusé** ce job.
L'erreur était invisible tant que tout tournait contre LocalStack, qui
n'évalue pas les conditions. La condition vise désormais l'environment
`production`, et un test de régression (`oidc_test.rego`) signale
l'ancien `sub`. Prérequis côté GitHub : reviewers obligatoires et
« Deployment branches » limitées à `main` sur cet environment.

<a id="verification-automatisee"></a>
### 🤖 Vérification automatisée des trust policies

Le test négatif ci-dessus n'est plus seulement décrit : il est rejoué
par des règles Rego (`policies/oidc.rego`, tests unitaires dans
`policies/oidc_test.rego`) qui contrôlent le contenu des trust
policies (règles 1 à 5, dont 2 bis et 5 bis) et des permissions (règles 6 à 10) des rôles,
**sans compte AWS** :

| # | Règle | Détecte |
|---|---|---|
| 1 | Pas de joker dans le `sub` | `repo:<ORG>/<REPO>:*` |
| 2 | Dépôt explicite | `sub` absent, ou `repo:*/<REPO>:...` |
| 2 bis | `sub` comparé en `StringEquals` | `StringLike` (ou tout opérateur à motif) sur le `sub` : un `*` futur élargirait la confiance en silence |
| 3 | Contexte attendu par rôle | `plan` ≠ `:pull_request`, `apply` ≠ `:environment:production` |
| 4 | Audience exacte | `aud` ≠ `sts.amazonaws.com` |
| 5 | Pas de `Principal "*"` | trust policy ouverte à toute identité |
| 5 bis | Dépôt attendu fourni de l'extérieur | `sub` ciblant un autre dépôt que `expected_repo` (donnée indépendante) |
| 6 | Pas d'action joker de service | `ec2:*`, `s3:*`, `*` |
| 6 bis | Pas de joker partiel hors lecture | `ec2:Run*`, `ec2:Delete*`… |
| 7 | Lecture seule vraiment en lecture | `s3:Get*`, `logs:Get*` pour le rôle `plan` |
| 8 | `Resource "*"` réservé à la lecture | action d'écriture sur `Resource "*"` |
| 9 | Pas de `NotAction` / `NotResource` | un `Allow` + `NotAction` autorise « presque tout » |
| 10 | Pas de policy illisible | policy managée AWS, externe, `managed_policy_arns`, `inline_policy` |

Les règles 6 à 10 examinent les policies **réellement attachées** à un
rôle assumable par GitHub (et non celles dont le nom porte un préfixe) ;
une policy attachée qu'on ne peut pas lire (managée AWS, externe) est
refusée. Cette portée a été élargie après que des contournements ont
été identifiés et testés : `NotAction`, `AdministratorAccess` attachée,
policy au nom anodin, joker partiel. Chacun a désormais un test négatif.

Particularité : ces règles lisent le **state** (`terraform show -json`
après un apply contre LocalStack) et non le plan, car
`assume_role_policy` y est inconnu avant l'apply (il dépend de l'ARN du
provider OIDC). Le job `plan` du pipeline les exécute à chaque pull
request, et `scripts/demo-local.sh` les rejoue en direct, y compris le
refus volontaire du `sub` en `:*`.

Tests unitaires (hors ligne) :

![conftest verify en CI — 90 tests, 90 passed](./captures/oidc-tests-unitaires.png)

Trust policies conformes sur un vrai state (16 contrôles `oidc`, 13 pour la simulation) :

![Trust policies conformes — 16 tests, 16 passed](./captures/oidc-state-conforme.png)

Refus volontaire : opérateur basculé en `StringLike` et `sub` élargi à `:*` (4 violations : joker,
`StringLike` sur les deux rôles, suffixe attendu absent) :

![Refus : StringLike et sub élargi — 4 violations](./captures/oidc-refus-joker.png)

#### Ce que LocalStack n'applique pas

Une fois les rôles appliqués sur LocalStack 4.4.0, j'ai appelé
`AssumeRoleWithWebIdentity` avec des jetons fictifs non signés :

| Jeton | Décision d'AWS | LocalStack |
|---|---|---|
| PR du bon dépôt → rôle `plan` | accepté | accepté |
| PR d'un autre dépôt → rôle `plan` | refusé | **accepté** |
| PR du bon dépôt → rôle `apply` | refusé | **accepté** |

LocalStack ne vérifie ni la signature du jeton ni les conditions `sub` /
`aud`. Un `AssumeRole` réussi contre lui ne prouve donc **rien** sur la
sécurité du design : c'est la preuve concrète, et non plus seulement
déclarée, de la limite de la partie 0.

#### Simulation de la décision d'AWS

Pour rendre observable l'*effet* des conditions malgré cela,
`policies/oidc_simulation.rego` rejoue l'évaluation documentée d'AWS
(`Allow` et `Deny` explicite prioritaire ; `StringEquals`,
`StringEqualsIgnoreCase`, `StringLike`, `StringNotEquals`,
`StringNotLike` ; ET entre conditions, OU entre valeurs d'une clé)
sur 10 jetons fictifs et vérifie la décision attendue pour
chaque rôle : PR du dépôt → `plan` accepté ; job de l'environment
`production` → `apply` accepté ; sont refusés : PR → `apply`, push sur
`main` → `plan`, push sur `main` **sans** environment → `apply`, autre
environment → `apply`, branche quelconque → `apply`, fork (autre
organisation) → `plan` et `apply`, mauvaise audience → `plan`. Sur le state avec `sub` élargi à `:*`, la
simulation signale qu'un push sur `main` assumerait le rôle `plan` — le
scénario d'attaque ci-dessus, désormais rejoué automatiquement.

**Limites de la simulation :** tout opérateur non modélisé
(`ForAnyValue:`, `IfExists`, `Bool`...) est signalé et rend la
simulation « non concluante » plutôt que d'être ignoré en silence
(ignorer un `Deny` aurait été permissif) ; les SCP et permission
boundaries ne sont pas modélisés ; la signature du jeton et le
thumbprint ne sont pas vérifiés. C'est une modélisation de la logique
AWS, pas AWS.

Exécution dans le pipeline, sur une pull request réelle (job `plan` :
règles EC2, règles OIDC, trust policies et simulation ; `apply` est
ignoré hors `main`) :

![Checks de la pull request : qualite et plan réussis, apply ignoré](./captures/ci-pr-checks-verts.png)

> ⚠️ **Limite inchangée** : ces contrôles vérifient le *contenu* des
> policies. L'enforcement réel par AWS (`AssumeRoleWithWebIdentity`
> accepté ou refusé selon le jeton) reste non exercé, faute de compte
> AWS.

---

<a id="second-moteur"></a>
#### Second moteur : test différentiel avec OpenBao

**Motivation.** La simulation est écrite par la même personne que les règles :
elle peut partager leurs angles morts. On la recoupe avec OpenBao (méthode
`jwt`), qui vérifie réellement la signature d'un jeton et compare ses claims.
Les rôles OpenBao sont construits **depuis le state Terraform** : les valeurs
testées sont celles de `oidc.tf`, pas une copie. Les mêmes jetons sont évalués
par OpenBao et par `oidc_simulation.rego` (via `policies/oidc_probe.rego`) ;
un désaccord signale un défaut dans l'un des deux.

**Deux modes.** `--local` signe les scénarios de la simulation avec une clé de
test (autre dépôt, `main`, mauvais environment, mauvaise audience). `--github`,
exécuté dans un job CI dédié (`jetons-reels`, seul à porter `id-token: write`,
ignoré pour les PR de forks), utilise le **vrai** jeton du job, dont la
signature est vérifiée via le JWKS de GitHub.

**Ce que le premier run a révélé.** Le job est passé au vert alors que le jeton
légitime d'une pull request était refusé par les deux moteurs : le `sub` émis
pour ce dépôt est `repo:Anne-LaureS@113637671/Pipeline-DevSecOps@1317703315:pull_request`
(`use_immutable_subject`), et non `repo:Anne-LaureS/Pipeline-DevSecOps:pull_request`
comme le supposait `oidc.tf`. Sur un vrai compte AWS, le rôle `plan` aurait
refusé les propres PR du dépôt. Deux corrections :

1. `oidc.tf` construit le `sub` comme le jeton (`github_org_id`,
   `github_repo_id`), ce qui protège aussi d'un renommage ou d'une recréation du
   dépôt par un tiers ;
2. le script vérifie une **intention** indépendante des deux moteurs (sur une
   PR, le jeton légitime est accepté par `plan` et refusé par `apply`), parce
   que deux moteurs qui refusent tout sont « d'accord ».

Après correction, en CI, avec le vrai jeton de la PR : `plan` ACCEPTÉ et
`apply` REFUSÉ par les deux moteurs, et tout est refusé avec une audience
incorrecte. Un test témoin (défaut injecté volontairement dans une copie de la
simulation) fait échouer le script avec le code 1 et la liste des désaccords.

**Limites, à lire avec le reste :**

- OpenBao compare des **valeurs exactes** ; ce n'est pas la sémantique de
  `StringLike` d'AWS. Le script n'accepte donc que des conditions
  `StringEquals`, où les deux sont équivalentes. On valide la logique des
  claims, pas l'évaluateur d'AWS.
- Ni OpenBao ni la simulation ne modélisent les `Deny` explicites, les
  opérateurs de condition autres que `StringEquals`, ni les SCP.
- La limite « jamais exercé sur un vrai AWS » reste vraie. La formulation
  exacte devient : **simulé et recoupé par un second moteur**.

<a id="partie-2"></a>
## 📸 2. Capture du commentaire de plan sur une pull request

Commentaire posté automatiquement par le job `plan` sur la pull
request `test-pipeline` → `main` (PR #2), après un run réussi contre
LocalStack :

![Terraform Plan commenté automatiquement sur la pull request](./captures/plan_comment.PNG)

---

<a id="partie-3"></a>
## 🚫 3. Messages de refus de politique

Tests réalisés en local contre LocalStack (`terraform/examples`), un
par un : décommenter/modifier la ressource visée pour violer une seule
règle à la fois, `terraform plan` + `conftest test`, capturer le
message, remettre en conformité, passer à la règle suivante. Résultat
final après correction : `8 tests, 8 passed, 0 failures` ✅ (à l'époque ; la couverture a depuis
été étendue, voir « Couverture étendue après revue » plus bas : **13 contrôles** aujourd'hui pour les
mêmes 4 règles)

| # | Règle violée | Ressource testée | Modification appliquée | Message de refus obtenu |
|---|---|---|---|---|
| 1️⃣ | SSH ouvert 0.0.0.0/0 | `aws_security_group.demo` | Bloc `ingress` remplacé par port 22 / `cidr_blocks = ["0.0.0.0/0"]` | `SECURITE: le security group 'aws_security_group.demo' ouvre le port SSH (22) a 0.0.0.0/0 (acces public non autorise)` |
| 2️⃣ | `http_tokens` requis (IMDSv2) | `aws_instance.demo` | `metadata_options.http_tokens` passé de `"required"` à `"optional"` | `SECURITE: l'instance 'aws_instance.demo' n'impose pas IMDSv2 (http_tokens doit valoir 'required')` |
| 3️⃣ | Disque racine non chiffré | `aws_instance.demo` | `root_block_device.encrypted` passé de `true` à `false` | `SECURITE: le disque racine de l'instance 'aws_instance.demo' n'est pas chiffre (encrypted doit valoir true)` |
| 4️⃣ | Tags obligatoires | `aws_security_group.demo` | Tag `Owner` retiré du bloc `tags` | `SECURITE: la ressource 'aws_security_group.demo' n'a pas les etiquettes obligatoires : {"Owner"}` |

Chaque violation a été testée isolément (une seule règle cassée à la
fois, les 3 autres restant conformes), ce qui confirme que
`policies/securite.rego` détecte chaque cas indépendamment et ne
masque pas les violations les unes derrière les autres.

### Couverture étendue après revue

Une relecture critique de `securite.rego` a montré, par des plans
fabriqués, que ces quatre règles laissaient passer des cas réels. Chacun
est maintenant détecté et a un test unitaire négatif
(`policies/securite_test.rego`) :

| Trou constaté | Pourquoi il passait | Correction |
|---|---|---|
| SSH avec `protocol = "-1"` sur `0.0.0.0/0` | avec `-1`, `from_port` et `to_port` valent 0 : la condition `to_port >= 22` échouait | « tout le trafic » est traité comme SSH exposé |
| `::/0` (IPv6) | seul `cidr_blocks` était lu | `ipv6_cidr_blocks`, `cidr_ipv4`, `cidr_ipv6` lus aussi |
| `aws_vpc_security_group_ingress_rule` | type de ressource non couvert | ajouté |
| `http_tokens` omis (calculé à l'apply) | valeur absente du plan : la comparaison ne se déclenchait pas | absent ou inconnu = refus |
| `encrypted` omis ; instance **sans** `root_block_device` | idem | absent ou inconnu = refus ; bloc manquant = refus |

Principe retenu : **ce qui n'est pas vérifiable est refusé**. Avant cette
correction, le contrôle donnait une assurance qu'il n'avait pas ; le
fait que la règle SSH annonçait bloquer « tout accès public » n'était
pas vrai pour le cas le plus large.


---

<a id="partie-4"></a>
## 🔍 4. Audit OWASP Top 10 CI/CD

| # | Risque OWASP CI/CD | Présent ? | Contrôle en place | Risque résiduel / à faire |
|---|---|---|---|---|
| CICD-SEC-1 | Contrôle d'accès pipeline insuffisant | 🟡 Partiellement | `environment: production` avec reviewers obligatoires sur `apply` ; branche `main` protégée (ruleset `protect-main` : pull request obligatoire, checks `qualite` et `plan` requis, branche à jour avant merge, suppression et force push interdits) ; rôles OIDC plan/apply écrits avec conditions `sub` distinctes, contrôlés statiquement par `policies/oidc.rego` | Faute de compte AWS, l'enforcement IAM réel (OIDC + trust policy) n'a **jamais été exécuté en conditions réelles**, seulement contre LocalStack qui ne simule pas la validation des permissions — **risque résiduel assumé, priorité haute si migration vers un vrai compte** |
| CICD-SEC-2 | Injection de code dans le pipeline | 🟢 Non | Toutes les actions épinglées par SHA de 40 caractères (pas de tag mutable) ; pas de `pull_request_target` utilisé | Un `github-script` avec du contenu de PR non filtré (ex : titre de PR injecté brut) resterait un vecteur si on l'ajoutait sans échappement — à surveiller si le pipeline évolue |
| CICD-SEC-3 | Dépendances tierces non sécurisées | 🟡 Partiellement | `trivy config` scanne l'IaC ; actions pinnées par SHA ; binaire Conftest téléchargé avec empreinte SHA-256 épinglée et vérifiée avant installation | Aucun scan des dépendances applicatives (SCA) type `trivy fs` / Dependabot n'est branché dans ce pipeline — **risque résiduel assumé** |
| CICD-SEC-4 | Politique de flux PBAC/CI/CD faible | 🟡 Partiellement | Séparation stricte plan (lecture) / apply (écriture) via deux rôles OIDC distincts | Permissions limitées à EC2 et à une région ; écritures nommées une à une, scopées par ARN et par tag `ManagedBy=terraform`. Reste `ec2:Describe*` sur `*` (non scopable par ARN). **Jamais testées sur un vrai compte** : à valider avec IAM Access Analyzer — **risque résiduel assumé** |
| CICD-SEC-5 | Configuration de build insuffisamment sécurisée | 🟢 Non | `permissions: {}` par défaut au niveau workflow, chaque job déclare le strict nécessaire | — |
| CICD-SEC-6 | Nettoyage insuffisant du système hébergeant le build | ⚪ Non applicable directement | Runners GitHub-hosted, éphémères par nature (VM détruite après chaque job) | On ne maîtrise pas la preuve de destruction ; on fait confiance à GitHub. Pour un contexte plus sensible, des self-hosted runners avec durcissement explicite seraient préférables |
| CICD-SEC-7 | Accès non contrôlé aux systèmes de gestion de configuration (SCM) | 🟡 Partiellement | Ruleset `protect-main` : pull request obligatoire, checks `qualite` et `plan` requis, branche à jour avant merge, suppression et force push interdits | **Aucune relecture par un tiers** (0 approbation requise : dépôt à un seul mainteneur).  Pas d'exigence de commits signés (GPG/Sigstore) ni de règle "linear history" — **risque résiduel assumé** |
| CICD-SEC-8 | Environnement CI/CD mal configuré | 🟡 Partiellement | `concurrency` sans `cancel-in-progress` pour éviter les states corrompus ; secrets gérés uniquement via OIDC (aucun secret statique stocké) | Le nom exact des rôles IAM et l'ARN de compte apparaissent en clair dans le workflow (`ACCOUNT_ID`) — pas un secret en soi mais de la reconnaissance facilitée si le repo devient public |
| CICD-SEC-9 | Exposition de secrets | 🟢 Non | Aucun secret AWS statique : uniquement OIDC + STS ; gitleaks bloquant sur chaque run | Gitleaks ne couvre que le contenu versionné, pas les logs de run (une variable mal loggée dans un `run:` resterait visible dans les logs Actions) — **risque résiduel assumé** |
| CICD-SEC-10 | Journalisation et visibilité insuffisantes du pipeline | 🟡 Partiellement | Logs Actions natifs conservés par GitHub ; commentaire de plan traçable sur chaque PR | Aucune centralisation externe des logs (SIEM), aucune alerte automatique en cas d'échec bloquant répété — à ajouter pour un contexte de production réel |

> ⚙️ **Note d'exécution réelle :** lors du premier passage du job
> `qualite` sur une vraie pull request, Trivy a effectivement bloqué le
> pipeline sur deux constats — le port 443 ouvert à 0.0.0.0/0 (attendu
> pour un service web public) et les wildcards IAM
> `ec2:*`/`ec2:Describe*` sur `resources = ["*"]` (identifiés
> ci-dessus comme CICD-SEC-4 ; depuis, les permissions ont été
> resserrées, il ne reste que `ec2:Describe*`). Plutôt que de baisser la sévérité du
> scan ou de le rendre non bloquant, ces deux constats ont été
> explicitement documentés et acceptés via un fichier `.trivyignore`
> avec justification (voir `.trivyignore` à la racine du dépôt) — ce
> qui prouve que le contrôle fonctionnait réellement en conditions
> live, et que la suppression est tracée plutôt que silencieuse.

---

<a id="partie-5"></a>
## 📚 5. Dissertation — trois principes de Saltzer & Schroeder

**🔒 Fail-safe defaults.** Le workflow déclare `permissions: {}` au
niveau global : par défaut, aucun job n'a le moindre droit, chaque
job doit explicitement lister ce dont il a besoin (`id-token: write`,
`pull-requests: write`...). C'est l'application directe du principe :
en cas d'oubli, l'échec est vers *moins* de privilèges, jamais vers
plus. **Au niveau IAM**, le défaut était initialement "large"
(`resources = ["*"]`, `ec2:*`) ; il a été resserré : actions nommées,
ARN limités à la région, écritures conditionnées au tag
`ManagedBy=terraform`. Reste `ec2:Describe*` sur `*`, non scopable.

**🎯 Least privilege.** La séparation en deux rôles OIDC (`plan` en
lecture seule, `apply` en écriture, chacun avec une condition `sub`
distincte) applique le moindre privilège au niveau de l'identité :
une pull request ne peut jamais obtenir de droits d'écriture, même si
le code du workflow était modifié dans la PR elle-même (la condition
`sub` empêche l'assomption du rôle apply hors de l'environment
`production`).
**Ce qui a évolué** : le rôle `apply` avait des actions comme `ec2:*`,
`s3:*`. Il n'a plus que les actions EC2 nécessaires, nommées une à une,
sans S3, RDS ni `iam:PassRole` (la stack n'en a pas besoin), et les
règles 6 à 10 de `oidc.rego` empêchent le retour en arrière.
**Limite** : ces permissions n'ont jamais été exercées sur un vrai
compte ; un rôle trop étroit échouerait au premier déploiement réel.

**🔁 Complete mediation.** Chaque `apply` sur `main` repasse par le job
`qualite` (fmt, gitleaks, trivy) et par `conftest` dans le job `plan`
avant d'être autorisé — aucun chemin ne permet de pousser une
configuration directement en `apply` sans revalidation systématique à
chaque run, même pour un changement mineur. **La violation** : le job
`apply` ne retélécharge pas le plan produit par le job `plan` (les
deux jobs tournent sur des événements différents, PR vs push main) ;
il relance son propre `terraform apply`, ce qui signifie que ce qui
est réellement appliqué n'est *techniquement pas* garanti identique à
ce qui a été montré en commentaire de PR et validé par conftest — une
médiation "complète" en apparence, mais avec un maillon faible entre
les deux runs, documenté comme risque résiduel dans le workflow.

**Ce qui renforce la médiation** : le ruleset `protect-main` exige les
checks `qualite` et `plan` et une branche à jour avant tout merge, et
interdit le push direct ; la médiation de `plan` (règles EC2, règles
OIDC, simulation) ne peut donc pas être contournée par un merge dont
les contrôles seraient rouges, absents ou périmés.