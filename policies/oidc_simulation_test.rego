package oidc_sim

import rego.v1

# Tests hors ligne de la simulation : `conftest verify --policy policies`.

provider_arn := "arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com"

sub_key := "token.actions.githubusercontent.com:sub"

aud_key := "token.actions.githubusercontent.com:aud"

trust(sub, aud) := {
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Allow",
		"Action": "sts:AssumeRoleWithWebIdentity",
		"Principal": {"Federated": provider_arn},
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

plan_ok := role("gha-terraform-plan", trust("repo:acme/infra:pull_request", "sts.amazonaws.com"))

apply_ok := role("gha-terraform-apply", trust("repo:acme/infra:environment:production", "sts.amazonaws.com"))

all_msgs := union({
	deny_prerequis,
	deny_pr_vers_plan,
	deny_env_production_vers_apply,
	deny_main_sans_env_vers_apply,
	deny_autre_env_vers_apply,
	deny_pr_vers_apply,
	deny_main_vers_plan,
	deny_branche_vers_apply,
	deny_autre_depot_vers_plan,
	deny_autre_depot_vers_apply,
	deny_mauvaise_audience,
})

has_msg(msgs, needle) if {
	some m in msgs
	contains(m, needle)
}

# --- Comportement conforme --------------------------------------------

test_trust_policies_conformes_aucun_ecart if {
	count(all_msgs) == 0 with input as state([plan_ok, apply_ok])
}

test_pr_du_depot_assume_le_role_plan if {
	r := role("gha-terraform-plan", trust("repo:acme/infra:pull_request", "sts.amazonaws.com"))
	decision(r, token("repo:acme/infra:pull_request", "sts.amazonaws.com")) == true
}

test_pr_du_depot_ne_peut_pas_assumer_le_role_apply if {
	decision(apply_ok, token("repo:acme/infra:pull_request", "sts.amazonaws.com")) == false
}

test_job_environment_production_assume_le_role_apply if {
	decision(apply_ok, token("repo:acme/infra:environment:production", "sts.amazonaws.com")) == true
}

test_push_main_sans_environment_ne_peut_pas_assumer_apply if {
	decision(apply_ok, token("repo:acme/infra:ref:refs/heads/main", "sts.amazonaws.com")) == false
}

test_autre_environment_refuse if {
	decision(apply_ok, token("repo:acme/infra:environment:staging", "sts.amazonaws.com")) == false
}

test_autre_depot_refuse if {
	decision(plan_ok, token("repo:attaquant/evil:pull_request", "sts.amazonaws.com")) == false
}

test_fork_refuse if {
	decision(plan_ok, token("repo:fork-user/infra:pull_request", "sts.amazonaws.com")) == false
}

test_mauvaise_audience_refusee if {
	decision(plan_ok, token("repo:acme/infra:pull_request", "autre.example.com")) == false
}

test_claim_absent_refuse if {
	decision(plan_ok, {"aud": "sts.amazonaws.com"}) == false
}

# --- Le joker élargit réellement la porte (l'attaque du rapport) ------

test_joker_laisse_passer_un_push_sur_main_vers_plan if {
	wide := role("gha-terraform-plan", trust("repo:acme/infra:*", "sts.amazonaws.com"))
	decision(wide, token("repo:acme/infra:ref:refs/heads/main", "sts.amazonaws.com")) == true
}

test_joker_laisse_passer_une_branche_quelconque if {
	wide := role("gha-terraform-plan", trust("repo:acme/infra:*", "sts.amazonaws.com"))
	decision(wide, token("repo:acme/infra:ref:refs/heads/evil", "sts.amazonaws.com")) == true
}

test_joker_ne_laisse_pas_passer_un_autre_depot if {
	wide := role("gha-terraform-plan", trust("repo:acme/infra:*", "sts.amazonaws.com"))
	decision(wide, token("repo:attaquant/evil:pull_request", "sts.amazonaws.com")) == false
}

# --- Les scénarios détectent une trust policy trop large --------------

test_joker_sur_plan_est_detecte if {
	wide := role("gha-terraform-plan", trust("repo:acme/infra:*", "sts.amazonaws.com"))
	has_msg(deny_main_vers_plan, "push sur main du depot -> role plan") with input as state([wide, apply_ok])
}

test_joker_sur_apply_est_detecte if {
	wide := role("gha-terraform-apply", trust("repo:acme/infra:*", "sts.amazonaws.com"))
	count(deny_pr_vers_apply | deny_branche_vers_apply) == 2 with input as state([plan_ok, wide])
}

test_org_joker_est_detecte if {
	wide := role("gha-terraform-plan", trust("repo:*/infra:pull_request", "sts.amazonaws.com"))
	has_msg(deny_autre_depot_vers_plan, "fork") with input as state([wide, apply_ok])
}

test_audience_non_verifiee_est_detectee if {
	doc := {"Statement": [{
		"Effect": "Allow",
		"Action": "sts:AssumeRoleWithWebIdentity",
		"Principal": {"Federated": provider_arn},
		"Condition": {"StringLike": {sub_key: "repo:acme/infra:pull_request"}},
	}]}
	has_msg(deny_mauvaise_audience, "mauvaise audience") with input as state([role("gha-terraform-plan", doc), apply_ok])
}

test_role_absent_est_signale if {
	has_msg(deny_prerequis, "absent du state") with input as state([apply_ok])
}

# --- Deny explicite, opérateurs négatifs, opérateurs non modélisés ----

doc_with(stmts) := {"Version": "2012-10-17", "Statement": stmts}

allow_pr := {
	"Effect": "Allow",
	"Action": "sts:AssumeRoleWithWebIdentity",
	"Principal": {"Federated": provider_arn},
	"Condition": {
		"StringEquals": {aud_key: "sts.amazonaws.com"},
		"StringLike": {sub_key: "repo:acme/infra:*"},
	},
}

test_deny_explicite_l_emporte_sur_allow if {
	deny_evil := {
		"Effect": "Deny",
		"Action": "sts:AssumeRoleWithWebIdentity",
		"Principal": {"Federated": provider_arn},
		"Condition": {"StringLike": {sub_key: "repo:acme/infra:ref:refs/heads/evil*"}},
	}
	r := role("gha-terraform-plan", doc_with([allow_pr, deny_evil]))
	decision(r, token("repo:acme/infra:pull_request", "sts.amazonaws.com")) == true
	decision(r, token("repo:acme/infra:ref:refs/heads/evil-branch", "sts.amazonaws.com")) == false
}

test_string_not_like_refuse_la_valeur_exclue if {
	stmt := {
		"Effect": "Allow",
		"Action": "sts:AssumeRoleWithWebIdentity",
		"Principal": {"Federated": provider_arn},
		"Condition": {
			"StringLike": {sub_key: "repo:acme/infra:*"},
			"StringNotLike": {sub_key: "repo:acme/infra:ref:refs/heads/*"},
		},
	}
	r := role("gha-terraform-plan", doc_with([stmt]))
	decision(r, token("repo:acme/infra:pull_request", "sts.amazonaws.com")) == true
	decision(r, token("repo:acme/infra:ref:refs/heads/main", "sts.amazonaws.com")) == false
}

test_condition_negative_vraie_si_cle_absente if {
	stmt := {
		"Effect": "Allow",
		"Action": "sts:AssumeRoleWithWebIdentity",
		"Principal": {"Federated": provider_arn},
		"Condition": {"StringNotEquals": {aud_key: "autre.example.com"}},
	}
	r := role("gha-terraform-plan", doc_with([stmt]))
	decision(r, {"sub": "x"}) == true
}

test_string_equals_ignore_case if {
	stmt := {
		"Effect": "Allow",
		"Action": "sts:AssumeRoleWithWebIdentity",
		"Principal": {"Federated": provider_arn},
		"Condition": {"StringEqualsIgnoreCase": {sub_key: "REPO:ACME/INFRA:pull_request"}},
	}
	r := role("gha-terraform-plan", doc_with([stmt]))
	decision(r, token("repo:acme/infra:pull_request", "sts.amazonaws.com")) == true
}

test_operateur_non_modelise_est_signale if {
	stmt := {
		"Effect": "Allow",
		"Action": "sts:AssumeRoleWithWebIdentity",
		"Principal": {"Federated": provider_arn},
		"Condition": {"ForAnyValue:StringLike": {sub_key: "repo:acme/infra:*"}},
	}
	has_msg(deny_prerequis, "non modelise") with input as state([role("gha-terraform-plan", doc_with([stmt])), apply_ok])
}

test_operateur_non_modelise_ne_donne_jamais_acces if {
	stmt := {
		"Effect": "Allow",
		"Action": "sts:AssumeRoleWithWebIdentity",
		"Principal": {"Federated": provider_arn},
		"Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
	}
	r := role("gha-terraform-plan", doc_with([stmt]))
	decision(r, token("repo:acme/infra:pull_request", "sts.amazonaws.com")) == false
}
