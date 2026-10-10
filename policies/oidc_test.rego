package oidc

import rego.v1

# Tests hors ligne des règles OIDC : `conftest verify --policy policies`
# (aucun LocalStack, aucun plan nécessaire — fixtures construites ici).

provider_arn := "arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com"

trust(principal, sub, aud) := {
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Allow",
		"Action": "sts:AssumeRoleWithWebIdentity",
		"Principal": principal,
		"Condition": {
			"StringEquals": {aud_key: aud},
			"StringLike": {sub_key: sub},
		},
	}],
}

role(name, doc) := {
	"type": "aws_iam_role",
	"address": sprintf("aws_iam_role.%s", [name]),
	"values": {"name": name, "assume_role_policy": json.marshal(doc)},
}

state(roles) := {"values": {"root_module": {"resources": roles}}}

federated := {"Federated": provider_arn}

good_plan := role("gha-terraform-plan", trust(federated, "repo:acme/infra:pull_request", "sts.amazonaws.com"))

good_apply := role("gha-terraform-apply", trust(federated, "repo:acme/infra:environment:production", "sts.amazonaws.com"))

has_msg(msgs, needle) if {
	some m in msgs
	contains(m, needle)
}

# --- Cas conforme -----------------------------------------------------

test_conforme_aucune_violation if {
	count(deny) == 0 with input as state([good_plan, good_apply])
}

# --- Règle 1 : joker dans le sub --------------------------------------

test_sub_avec_joker_refuse if {
	bad := role("gha-terraform-plan", trust(federated, "repo:acme/infra:*", "sts.amazonaws.com"))
	has_msg(deny, "joker") with input as state([bad])
}

# --- Règle 2 : dépôt explicite ----------------------------------------

test_sub_org_joker_refuse if {
	bad := role("gha-terraform-plan", trust(federated, "repo:*/infra:pull_request", "sts.amazonaws.com"))
	has_msg(deny, "depot") with input as state([bad])
}

test_sub_absent_refuse if {
	doc := {"Statement": [{
		"Effect": "Allow",
		"Action": "sts:AssumeRoleWithWebIdentity",
		"Principal": federated,
		"Condition": {"StringEquals": {aud_key: "sts.amazonaws.com"}},
	}]}
	has_msg(deny, "aucune condition sur le sub") with input as state([role("gha-terraform-plan", doc)])
}

# --- Règle 3 : événement attendu par rôle -----------------------------

test_plan_ne_doit_pas_accepter_main if {
	bad := role("gha-terraform-plan", trust(federated, "repo:acme/infra:ref:refs/heads/main", "sts.amazonaws.com"))
	has_msg(deny, ":pull_request") with input as state([bad])
}

test_apply_ne_doit_pas_accepter_pull_request if {
	bad := role("gha-terraform-apply", trust(federated, "repo:acme/infra:pull_request", "sts.amazonaws.com"))
	has_msg(deny, ":environment:production") with input as state([bad])
}

# Régression : un job apply qui déclare `environment:` reçoit
# sub=...:environment:<nom>, jamais ...:ref:refs/heads/main. Une condition
# sur le ref refuserait donc ce job sur un vrai compte AWS.
test_apply_sur_ref_main_est_signale if {
	bad := role("gha-terraform-apply", trust(federated, "repo:acme/infra:ref:refs/heads/main", "sts.amazonaws.com"))
	has_msg(deny, ":environment:production") with input as state([bad])
}

# --- Règle 4 : audience -----------------------------------------------

test_aud_incorrecte_refusee if {
	bad := role("gha-terraform-plan", trust(federated, "repo:acme/infra:pull_request", "autre.example.com"))
	has_msg(deny, "aud") with input as state([bad])
}

test_aud_liste_elargie_refusee if {
	bad := role("gha-terraform-plan", trust(federated, "repo:acme/infra:pull_request", ["sts.amazonaws.com", "autre.example.com"]))
	has_msg(deny, "aud") with input as state([bad])
}

# --- Règle 5 : principal * --------------------------------------------

test_principal_etoile_refuse if {
	bad := role("gha-terraform-plan", trust("*", "repo:acme/infra:pull_request", "sts.amazonaws.com"))
	has_msg(deny, "Principal '*'") with input as state([bad])
}

test_principal_aws_etoile_refuse if {
	bad := role("autre-role", trust({"AWS": "*"}, "x", "y"))
	has_msg(deny, "Principal '*'") with input as state([bad])
}

# --- Les rôles non-OIDC ne déclenchent pas les règles 1 à 4 -----------

test_role_non_oidc_ignore if {
	doc := {"Statement": [{
		"Effect": "Allow",
		"Action": "sts:AssumeRole",
		"Principal": {"Service": "ec2.amazonaws.com"},
	}]}
	count(deny) == 0 with input as state([role("ec2-role", doc)])
}
