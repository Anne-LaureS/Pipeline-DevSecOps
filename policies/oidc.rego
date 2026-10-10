package oidc

import rego.v1

# Règles sur les trust policies des rôles IAM assumés via OIDC GitHub Actions.
#
# Entrée attendue : la sortie de `terraform show -json` (STATE), et non celle
# d'un plan. Dans un plan, `assume_role_policy` dépend de l'ARN du provider
# OIDC, qui n'existe pas avant l'apply : le champ y est inconnu et invisible
# pour conftest. Après un apply (par exemple sur LocalStack), il est en clair.
#
# Usage :
#   terraform show -json > state.json
#   conftest test state.json --policy policies --namespace oidc

sub_key := "token.actions.githubusercontent.com:sub"

aud_key := "token.actions.githubusercontent.com:aud"

# Suffixe du `sub` attendu pour chaque rôle (nom du rôle -> événement GitHub).
expected_sub_suffix := {
	"gha-terraform-plan": ":pull_request",
	"gha-terraform-apply": ":environment:production",
}

# --- Helpers ---------------------------------------------------------

as_array(x) := x if is_array(x)

as_array(x) := [x] if not is_array(x)

iam_roles contains r if {
	some r in input.values.root_module.resources
	r.type == "aws_iam_role"
}

statements(r) := as_array(json.unmarshal(r.values.assume_role_policy).Statement)

# Rôle assumable par le provider OIDC GitHub (principal Federated).
github_oidc_role(r) if {
	some st in statements(r)
	some p in as_array(st.Principal.Federated)
	contains(p, "token.actions.githubusercontent.com")
}

# Toutes les valeurs d'une clé de condition, quel que soit l'opérateur
# (StringEquals, StringLike...) et qu'elle soit chaîne ou liste.
claim_values(st, key) := {v |
	some _, conds in st.Condition
	some v in as_array(conds[key])
}

oidc_statements(r) := [st |
	some st in statements(r)
	some p in as_array(st.Principal.Federated)
	contains(p, "token.actions.githubusercontent.com")
]

# ======================================================================
# Règle 1 — Aucun joker dans le `sub`
# ======================================================================

deny contains msg if {
	some r in iam_roles
	github_oidc_role(r)
	some st in oidc_statements(r)
	some sub in claim_values(st, sub_key)
	regex.match(`[*?]`, sub)
	msg := sprintf(
		"SECURITE: le role '%s' autorise un sub avec joker ('%s') : n'importe quel contexte du depot pourrait l'assumer",
		[r.address, sub],
	)
}

# ======================================================================
# Règle 2 — Le `sub` désigne explicitement un dépôt : repo:<org>/<repo>:...
# ======================================================================

deny contains msg if {
	some r in iam_roles
	github_oidc_role(r)
	some st in oidc_statements(r)
	some sub in claim_values(st, sub_key)
	not regex.match(`^repo:[^/*?:]+/[^/*?:]+:`, sub)
	msg := sprintf(
		"SECURITE: le role '%s' a un sub ('%s') qui ne cible pas explicitement un depot (repo:<org>/<repo>:...)",
		[r.address, sub],
	)
}

deny contains msg if {
	some r in iam_roles
	github_oidc_role(r)
	some st in oidc_statements(r)
	count(claim_values(st, sub_key)) == 0
	msg := sprintf(
		"SECURITE: le role '%s' n'a aucune condition sur le sub : tout depot GitHub pourrait l'assumer",
		[r.address],
	)
}

# ======================================================================
# Règle 2 bis — le sub se compare avec StringEquals (valeur exacte)
# StringLike (ou tout opérateur à motif) laisse un `*` futur élargir la
# confiance en silence ; StringEquals le traiterait comme un littéral.
# ======================================================================

deny contains msg if {
	some r in iam_roles
	github_oidc_role(r)
	some st in oidc_statements(r)
	some op, conds in st.Condition
	op != "StringEquals"
	sub_key in object.keys(conds)
	msg := sprintf(
		"SECURITE: le role '%s' compare le sub avec %s : utiliser StringEquals (aucun joker attendu)",
		[r.address, op],
	)
}

# ======================================================================
# Règle 3 — plan : uniquement pull_request ; apply : uniquement l'environment
# production (un job qui déclare `environment:` reçoit sub=...:environment:<nom>)
# ======================================================================

deny contains msg if {
	some r in iam_roles
	github_oidc_role(r)
	suffix := expected_sub_suffix[r.values.name]
	some st in oidc_statements(r)
	some sub in claim_values(st, sub_key)
	not regex.match(sprintf("^repo:[^/*?:]+/[^/*?:]+%s$", [suffix]), sub)
	msg := sprintf(
		"SECURITE: le role '%s' doit avoir un sub finissant par '%s' (trouve : '%s')",
		[r.address, suffix, sub],
	)
}

# ======================================================================
# Règle 4 — aud exactement sts.amazonaws.com
# ======================================================================

deny contains msg if {
	some r in iam_roles
	github_oidc_role(r)
	some st in oidc_statements(r)
	claim_values(st, aud_key) != {"sts.amazonaws.com"}
	msg := sprintf(
		"SECURITE: le role '%s' doit exiger aud = 'sts.amazonaws.com' exactement (trouve : %v)",
		[r.address, claim_values(st, aud_key)],
	)
}

# ======================================================================
# Règle 5 — Aucun Principal "*" dans une trust policy (tous les rôles)
# ======================================================================

wildcard_principal(st) if st.Principal == "*"

wildcard_principal(st) if {
	some _, p in st.Principal
	"*" in as_array(p)
}

deny contains msg if {
	some r in iam_roles
	some st in statements(r)
	st.Effect == "Allow"
	wildcard_principal(st)
	msg := sprintf(
		"SECURITE: la trust policy du role '%s' autorise un Principal '*' (n'importe quelle identite)",
		[r.address],
	)
}

# ======================================================================
# Règle 5 bis — Dépôt attendu fourni de l'extérieur (donnée indépendante)
# Sans `data.expected_repo`, cette règle est inactive. Avec :
#   conftest test state.json --policy policies --namespace oidc --data expected/
# où expected/expected.json contient {"expected_repo": "<org>/<repo>"}.
# ======================================================================

deny contains msg if {
	expected := data.expected_repo
	some r in iam_roles
	github_oidc_role(r)
	some st in oidc_statements(r)
	some sub in claim_values(st, sub_key)
	not startswith(sub, sprintf("repo:%s:", [expected]))
	msg := sprintf(
		"SECURITE: le role '%s' cible un depot different de celui attendu (%s) : sub '%s'",
		[r.address, expected, sub],
	)
}

# ======================================================================
# Règles 6 à 9 — Permissions des rôles OIDC GitHub (moindre privilège)
#
# Les documents examinés sont ceux RÉELLEMENT attachés à un rôle assumable par
# GitHub (attachement ou policy inline), et non ceux dont le nom commence par
# un préfixe : un nom ne prouve rien. Une policy qu'on ne peut pas lire
# (managée AWS, externe) est refusée : on ne valide pas ce qu'on ne voit pas.
# ======================================================================

resources_of_type(t) := {r | some r in input.values.root_module.resources; r.type == t}

# Attachements rôle -> ARN de policy, via aws_iam_role_policy_attachment
# (un rôle) ou aws_iam_policy_attachment (liste `roles`).
role_attachments contains {"role": r.values.name, "arn": a.values.policy_arn, "address": a.address} if {
	some r in iam_roles
	github_oidc_role(r)
	some a in resources_of_type("aws_iam_role_policy_attachment")
	a.values.role == r.values.name
}

role_attachments contains {"role": r.values.name, "arn": a.values.policy_arn, "address": a.address} if {
	some r in iam_roles
	github_oidc_role(r)
	some a in resources_of_type("aws_iam_policy_attachment")
	r.values.name in a.values.roles
}

attached_documents contains d if {
	some att in role_attachments
	some p in resources_of_type("aws_iam_policy")
	p.values.arn == att.arn
	d := {"role": att.role, "name": p.values.name, "document": p.values.policy}
}

attached_documents contains d if {
	some r in iam_roles
	github_oidc_role(r)
	some p in resources_of_type("aws_iam_role_policy")
	p.values.role == r.values.name
	d := {"role": r.values.name, "name": p.values.name, "document": p.values.policy}
}

doc_statements(d) := as_array(json.unmarshal(d.document).Statement)

known_policy_arns contains p.values.arn if some p in resources_of_type("aws_iam_policy")

# Actions qui donnent accès à du CONTENU (données, journaux, secrets) :
# interdites à une policy « lecture seule ».
data_read_actions := {
	"s3:getobject",
	"logs:getlogevents",
	"secretsmanager:getsecretvalue",
	"ssm:getparameter",
	"kms:decrypt",
}

action_covers(pattern, action) if {
	regex.match(sprintf("^%s$", [replace(lower(pattern), "*", ".*")]), action)
}

# Règle 6 — pas d'action joker de service entier (s3:*, ec2:*, *)
deny contains msg if {
	some d in attached_documents
	some st in doc_statements(d)
	st.Effect == "Allow"
	some a in as_array(st.Action)
	regex.match(`^(\*|[A-Za-z0-9-]+:\*)$`, a)
	msg := sprintf(
		"SECURITE: la policy '%s' (role %s) autorise '%s' (joker de service entier)",
		[d.name, d.role, a],
	)
}

# Règle 6 bis — pas de joker partiel hors lecture (ec2:Run*, ec2:*Instances...)
deny contains msg if {
	some d in attached_documents
	some st in doc_statements(d)
	st.Effect == "Allow"
	some a in as_array(st.Action)
	regex.match(`[*?]`, a)
	not regex.match(`^(\*|[A-Za-z0-9-]+:\*)$`, a)
	not regex.match(`^[a-z0-9-]+:(describe|list|get)[a-z0-9]*\*?$`, lower(a))
	msg := sprintf(
		"SECURITE: la policy '%s' (role %s) autorise '%s' (joker partiel hors lecture)",
		[d.name, d.role, a],
	)
}

# Règle 7 — la policy du rôle plan ne doit pas couvrir de lecture de contenu
deny contains msg if {
	some d in attached_documents
	d.role == "gha-terraform-plan"
	some st in doc_statements(d)
	st.Effect == "Allow"
	some a in as_array(st.Action)
	some c in data_read_actions
	action_covers(a, c)
	msg := sprintf(
		"SECURITE: la policy lecture seule '%s' autorise '%s', qui couvre la lecture de contenu (%s)",
		[d.name, a, c],
	)
}

# Règle 8 — Resource "*" réservé aux actions de lecture (Describe/List/Get)
deny contains msg if {
	some d in attached_documents
	some st in doc_statements(d)
	st.Effect == "Allow"
	"*" in as_array(st.Resource)
	some a in as_array(st.Action)
	not regex.match(`^[a-z0-9-]+:(describe|list|get)`, lower(a))
	msg := sprintf(
		"SECURITE: la policy '%s' (role %s) autorise l'action d'ecriture '%s' sur Resource '*'",
		[d.name, d.role, a],
	)
}

# Règle 9 — NotAction / NotResource interdits (un Allow + NotAction = presque tout)
deny contains msg if {
	some d in attached_documents
	some st in doc_statements(d)
	st.Effect == "Allow"
	some k in {"NotAction", "NotResource"}
	object.get(st, k, null) != null
	msg := sprintf(
		"SECURITE: la policy '%s' (role %s) utilise %s dans un Allow : interdit",
		[d.name, d.role, k],
	)
}

# Règle 10 — toute policy attachée qu'on ne peut pas lire est refusée
deny contains msg if {
	some att in role_attachments
	not att.arn in known_policy_arns
	msg := sprintf(
		"SECURITE: le role '%s' porte la policy '%s', non verifiable (geree par AWS ou externe)",
		[att.role, att.arn],
	)
}

deny contains msg if {
	some r in iam_roles
	github_oidc_role(r)
	count(object.get(r.values, "managed_policy_arns", [])) > 0
	msg := sprintf(
		"SECURITE: le role '%s' declare managed_policy_arns : non verifiable, utiliser des attachements",
		[r.address],
	)
}

deny contains msg if {
	some r in iam_roles
	github_oidc_role(r)
	count(object.get(r.values, "inline_policy", [])) > 0
	msg := sprintf(
		"SECURITE: le role '%s' declare inline_policy : non verifiable, utiliser aws_iam_role_policy",
		[r.address],
	)
}
