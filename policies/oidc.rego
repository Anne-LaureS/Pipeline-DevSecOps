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
# Règle 3 — plan : uniquement pull_request ; apply : uniquement l'environment
# production (un job qui déclare `environment:` reçoit sub=...:environment:<nom>)
# ======================================================================

deny contains msg if {
	some r in iam_roles
	github_oidc_role(r)
	suffix := expected_sub_suffix[r.values.name]
	some st in oidc_statements(r)
	some sub in claim_values(st, sub_key)
	not endswith(sub, suffix)
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
# Règles 6 à 8 — Permissions des rôles gha-terraform-* (moindre privilège)
# Lues dans le state : aws_iam_policy.values.policy (document JSON).
# ======================================================================

managed_policies contains p if {
	some p in input.values.root_module.resources
	p.type == "aws_iam_policy"
	startswith(p.values.name, "gha-terraform-")
}

policy_statements(p) := as_array(json.unmarshal(p.values.policy).Statement)

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
	some p in managed_policies
	some st in policy_statements(p)
	st.Effect == "Allow"
	some a in as_array(st.Action)
	regex.match(`^(\*|[A-Za-z0-9-]+:\*)$`, a)
	msg := sprintf(
		"SECURITE: la policy '%s' autorise '%s' (joker de service entier)",
		[p.values.name, a],
	)
}

# Règle 7 — la policy lecture seule ne doit pas couvrir de lecture de contenu
deny contains msg if {
	some p in managed_policies
	p.values.name == "gha-terraform-plan-readonly"
	some st in policy_statements(p)
	st.Effect == "Allow"
	some a in as_array(st.Action)
	some d in data_read_actions
	action_covers(a, d)
	msg := sprintf(
		"SECURITE: la policy lecture seule '%s' autorise '%s', qui couvre la lecture de contenu (%s)",
		[p.values.name, a, d],
	)
}

# Règle 8 — Resource "*" réservé aux actions de lecture (Describe/List/Get)
deny contains msg if {
	some p in managed_policies
	some st in policy_statements(p)
	st.Effect == "Allow"
	"*" in as_array(st.Resource)
	some a in as_array(st.Action)
	not regex.match(`^[a-z0-9-]+:(describe|list|get)`, lower(a))
	msg := sprintf(
		"SECURITE: la policy '%s' autorise l'action d'ecriture '%s' sur Resource '*'",
		[p.values.name, a],
	)
}
