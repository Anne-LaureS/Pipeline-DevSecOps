package oidc_sim

import rego.v1

# Simulation de la décision d'AWS pour AssumeRoleWithWebIdentity.
#
# Pourquoi : LocalStack n'applique pas les trust policies (il accepte un jeton
# d'un autre dépôt). Faute de compte AWS, on rejoue donc ici la logique
# d'évaluation documentée par AWS sur des jetons fictifs, et on vérifie que le
# comportement obtenu est celui attendu pour chaque rôle.
#
# Modélisé : statements Allow et Deny (un Deny explicite l'emporte toujours),
# opérateurs StringEquals, StringEqualsIgnoreCase, StringLike, StringNotEquals
# et StringNotLike (une clé absente rend vraie une condition négative, fausse
# une condition positive).
#
# Limites assumées (c'est une SIMULATION, pas AWS) :
#   - tout autre opérateur (ForAnyValue:, IfExists, Bool...) est SIGNALÉ par
#     la règle deny_prerequis au lieu d'être ignoré en silence ;
#   - les SCP et permission boundaries ne sont pas modélisés ;
#   - la signature du jeton et l'empreinte du provider ne sont pas vérifiées.
#
# Entrée : le state (`terraform show -json` après apply sur LocalStack).
#   conftest test state.json --policy policies --namespace oidc_sim

issuer := "token.actions.githubusercontent.com"

audience := "sts.amazonaws.com"

# --- Moteur d'évaluation ---------------------------------------------

as_array(x) := x if is_array(x)

as_array(x) := [x] if not is_array(x)

roles_by_name[name] := r if {
	some r in input.values.root_module.resources
	r.type == "aws_iam_role"
	name := r.values.name
}

statements(r) := as_array(json.unmarshal(r.values.assume_role_policy).Statement)

# Motif StringLike -> expression régulière ancrée ('*' = suite quelconque,
# '?' = un caractère ; le reste est littéral).
glob_to_regex(pattern) := sprintf("^%s$", [expanded]) if {
	escaped := regex.replace(pattern, `[.+^${}()|\[\]\\]`, `\${0}`)
	star := replace(escaped, "*", ".*")
	expanded := replace(star, "?", ".")
}

# "token.actions.githubusercontent.com:sub" -> "sub"
claim_name(key) := array.reverse(split(key, ":"))[0]

supported_operators := {
	"StringEquals", "StringEqualsIgnoreCase", "StringLike",
	"StringNotEquals", "StringNotLike",
}

# Opérateur négatif -> opérateur positif correspondant.
negated := {"StringNotEquals": "StringEquals", "StringNotLike": "StringLike"}

operator_matches("StringEquals", actual, expected) if actual == expected

operator_matches("StringEqualsIgnoreCase", actual, expected) if lower(actual) == lower(expected)

operator_matches("StringLike", actual, expected) if regex.match(glob_to_regex(expected), actual)

# Valeur du claim visé par une clé de condition ; indéfinie si la clé n'est
# pas du provider GitHub ou si le jeton ne porte pas ce claim.
claim_value(claims, key) := claims[claim_name(key)] if startswith(key, concat("", [issuer, ":"]))

# Opérateur positif : au moins une valeur doit correspondre ; clé absente = faux.
key_ok(op, claims, key, vals) if {
	op in supported_operators
	not negated[op]
	actual := claim_value(claims, key)
	some expected in as_array(vals)
	operator_matches(op, actual, expected)
}

# Opérateur négatif : aucune valeur ne doit correspondre ; clé absente = vrai.
key_ok(op, claims, key, vals) if {
	positive := negated[op]
	actual := claim_value(claims, key)
	every expected in as_array(vals) {
		not operator_matches(positive, actual, expected)
	}
}

key_ok(op, claims, key, _) if {
	negated[op]
	not claim_value(claims, key)
}

# Toutes les conditions (ET entre opérateurs et clés).
conditions_ok(st, claims) if {
	every op, conds in object.get(st, "Condition", {}) {
		every key, vals in conds {
			key_ok(op, claims, key, vals)
		}
	}
}

# Le statement vise-t-il cette action et le provider OIDC GitHub ?
applies(st) if {
	"sts:AssumeRoleWithWebIdentity" in as_array(st.Action)
	st.Principal == "*"
}

applies(st) if {
	"sts:AssumeRoleWithWebIdentity" in as_array(st.Action)
	some p in as_array(st.Principal.Federated)
	endswith(p, concat("", [":oidc-provider/", issuer]))
}

# Un Deny explicite l'emporte sur tout Allow.
explicitly_denied(r, claims) if {
	some st in statements(r)
	st.Effect == "Deny"
	applies(st)
	conditions_ok(st, claims)
}

allowed(r, claims) if {
	some st in statements(r)
	st.Effect == "Allow"
	applies(st)
	conditions_ok(st, claims)
	not explicitly_denied(r, claims)
}

decision(r, claims) := true if allowed(r, claims)

decision(r, claims) := false if not allowed(r, claims)

token(sub, aud) := {"sub": sub, "aud": aud}

# --- Scénarios attendus ----------------------------------------------

# Le dépôt de référence est lu dans la condition `sub` du rôle apply
# (repo:<org>/<repo>:...), pour ne pas coder en dur un nom de dépôt.
repo := m[0][1] if {
	some st in statements(roles_by_name["gha-terraform-apply"])
	some _, conds in st.Condition
	some v in as_array(conds[sprintf("%s:sub", [issuer])])
	m := regex.find_all_string_submatch_n(`^repo:([^:*?]+/[^:*?]+):`, v, 1)
	count(m) > 0
}

repo_name := split(repo, "/")[1]

scenarios := {
	"pr_vers_plan": {
		"nom": "PR du depot -> role plan",
		"role": "gha-terraform-plan",
		"sub": sprintf("repo:%s:pull_request", [repo]),
		"aud": audience,
		"attendu": true,
	},
	"env_production_vers_apply": {
		"nom": "job du depot sur l'environment production -> role apply",
		"role": "gha-terraform-apply",
		"sub": sprintf("repo:%s:environment:production", [repo]),
		"aud": audience,
		"attendu": true,
	},
	"main_sans_env_vers_apply": {
		"nom": "push sur main sans environment -> role apply",
		"role": "gha-terraform-apply",
		"sub": sprintf("repo:%s:ref:refs/heads/main", [repo]),
		"aud": audience,
		"attendu": false,
	},
	"autre_env_vers_apply": {
		"nom": "job du depot sur un autre environment -> role apply",
		"role": "gha-terraform-apply",
		"sub": sprintf("repo:%s:environment:staging", [repo]),
		"aud": audience,
		"attendu": false,
	},
	"pr_vers_apply": {
		"nom": "PR du depot -> role apply",
		"role": "gha-terraform-apply",
		"sub": sprintf("repo:%s:pull_request", [repo]),
		"aud": audience,
		"attendu": false,
	},
	"main_vers_plan": {
		"nom": "push sur main du depot -> role plan",
		"role": "gha-terraform-plan",
		"sub": sprintf("repo:%s:ref:refs/heads/main", [repo]),
		"aud": audience,
		"attendu": false,
	},
	"branche_vers_apply": {
		"nom": "push sur une branche quelconque -> role apply",
		"role": "gha-terraform-apply",
		"sub": sprintf("repo:%s:ref:refs/heads/feature-x", [repo]),
		"aud": audience,
		"attendu": false,
	},
	"autre_depot_vers_plan": {
		"nom": "PR d'un fork (autre organisation) -> role plan",
		"role": "gha-terraform-plan",
		"sub": sprintf("repo:attaquant/%s:pull_request", [repo_name]),
		"aud": audience,
		"attendu": false,
	},
	"autre_depot_vers_apply": {
		"nom": "environment production d'un fork (autre organisation) -> role apply",
		"role": "gha-terraform-apply",
		"sub": sprintf("repo:attaquant/%s:environment:production", [repo_name]),
		"aud": audience,
		"attendu": false,
	},
	"mauvaise_audience": {
		"nom": "PR du depot avec une mauvaise audience -> role plan",
		"role": "gha-terraform-plan",
		"sub": sprintf("repo:%s:pull_request", [repo]),
		"aud": "autre.example.com",
		"attendu": false,
	},
}

label(true) := "ACCEPTE"

label(false) := "REFUSE"

check(id) := msg if {
	sc := scenarios[id]
	r := roles_by_name[sc.role]
	got := decision(r, token(sc.sub, sc.aud))
	got != sc.attendu
	msg := sprintf(
		"SIMULATION: %s : %s par la trust policy, %s attendu (sub=%s)",
		[sc.nom, label(got), label(sc.attendu), sc.sub],
	)
}

# --- Règles conftest : une par scénario ------------------------------

deny_prerequis contains msg if {
	not repo
	msg := "SIMULATION: impossible d'identifier le depot dans le sub du role gha-terraform-apply"
}

deny_prerequis contains msg if {
	some name in {"gha-terraform-plan", "gha-terraform-apply"}
	not roles_by_name[name]
	msg := sprintf("SIMULATION: le role '%s' est absent du state", [name])
}

# Un opérateur non modélisé rend la simulation non concluante : on le signale
# au lieu de l'ignorer (ignorer un Deny serait permissif).
deny_prerequis contains msg if {
	some name in {"gha-terraform-plan", "gha-terraform-apply"}
	some st in statements(roles_by_name[name])
	some op, _ in object.get(st, "Condition", {})
	not op in supported_operators
	msg := sprintf(
		"SIMULATION: operateur '%s' non modelise dans le role '%s' : simulation non concluante",
		[op, name],
	)
}

deny_pr_vers_plan contains check("pr_vers_plan")

deny_env_production_vers_apply contains check("env_production_vers_apply")

deny_main_sans_env_vers_apply contains check("main_sans_env_vers_apply")

deny_autre_env_vers_apply contains check("autre_env_vers_apply")

deny_pr_vers_apply contains check("pr_vers_apply")

deny_main_vers_plan contains check("main_vers_plan")

deny_branche_vers_apply contains check("branche_vers_apply")

deny_autre_depot_vers_plan contains check("autre_depot_vers_plan")

deny_autre_depot_vers_apply contains check("autre_depot_vers_apply")

deny_mauvaise_audience contains check("mauvaise_audience")
