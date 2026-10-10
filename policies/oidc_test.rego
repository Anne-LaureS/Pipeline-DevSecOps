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
			"StringEquals": {aud_key: aud, sub_key: sub},
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

# --- Règles 6 à 10 : permissions des rôles ----------------------------
# Les règles examinent les documents RÉELLEMENT attachés à un rôle OIDC
# GitHub : chaque fixture contient le rôle, la policy et son attachement.

arn_of(name) := sprintf("arn:aws:iam::000000000000:policy/%s", [name])

policy_res(name, stmts) := {
	"type": "aws_iam_policy",
	"address": sprintf("aws_iam_policy.%s", [name]),
	"values": {
		"name": name,
		"arn": arn_of(name),
		"policy": json.marshal({"Version": "2012-10-17", "Statement": stmts}),
	},
}

attachment(role_name, arn) := {
	"type": "aws_iam_role_policy_attachment",
	"address": sprintf("aws_iam_role_policy_attachment.%s", [role_name]),
	"values": {"role": role_name, "policy_arn": arn},
}

inline_policy(role_name, stmts) := {
	"type": "aws_iam_role_policy",
	"address": sprintf("aws_iam_role_policy.%s", [role_name]),
	"values": {
		"name": "inline",
		"role": role_name,
		"policy": json.marshal({"Version": "2012-10-17", "Statement": stmts}),
	},
}

# role + policy + attachement pour le rôle apply
apply_with(name, stmts) := [good_plan, good_apply, policy_res(name, stmts), attachment("gha-terraform-apply", arn_of(name))]

# role + policy + attachement pour le rôle plan
plan_with(name, stmts) := [good_plan, good_apply, policy_res(name, stmts), attachment("gha-terraform-plan", arn_of(name))]

read_ec2 := {"Effect": "Allow", "Action": ["ec2:Describe*"], "Resource": "*"}

create_ec2 := {
	"Effect": "Allow",
	"Action": ["ec2:RunInstances", "ec2:CreateSecurityGroup"],
	"Resource": "arn:aws:ec2:eu-west-3:*:*",
}

test_permissions_conformes_aucune_violation if {
	res := [
		good_plan, good_apply,
		policy_res("p-plan", [read_ec2]), attachment("gha-terraform-plan", arn_of("p-plan")),
		policy_res("p-apply", [read_ec2, create_ec2]), attachment("gha-terraform-apply", arn_of("p-apply")),
	]
	count(deny) == 0 with input as state(res)
}

test_action_joker_de_service_refusee if {
	st := {"Effect": "Allow", "Action": ["ec2:*"], "Resource": "arn:aws:ec2:eu-west-3:*:*"}
	has_msg(deny, "joker de service entier") with input as state(apply_with("p", [st]))
}

test_action_etoile_seule_refusee if {
	st := {"Effect": "Allow", "Action": "*", "Resource": "arn:aws:ec2:eu-west-3:*:*"}
	has_msg(deny, "joker de service entier") with input as state(apply_with("p", [st]))
}

test_lecture_seule_ne_couvre_pas_s3_getobject if {
	st := {"Effect": "Allow", "Action": ["s3:Get*"], "Resource": "*"}
	has_msg(deny, "s3:getobject") with input as state(plan_with("p", [st]))
}

test_lecture_seule_ne_couvre_pas_logs_getlogevents if {
	st := {"Effect": "Allow", "Action": ["logs:Get*"], "Resource": "*"}
	has_msg(deny, "logs:getlogevents") with input as state(plan_with("p", [st]))
}

test_lecture_bornee_s3_bucket_acceptee if {
	st := {"Effect": "Allow", "Action": ["s3:GetBucket*", "s3:ListBucket"], "Resource": "*"}
	not has_msg(deny, "lecture de contenu") with input as state(plan_with("p", [st]))
}

test_ecriture_sur_resource_etoile_refusee if {
	st := {"Effect": "Allow", "Action": ["ec2:TerminateInstances"], "Resource": "*"}
	has_msg(deny, "sur Resource '*'") with input as state(apply_with("p", [st]))
}

test_lecture_sur_resource_etoile_acceptee if {
	not has_msg(deny, "sur Resource '*'") with input as state(apply_with("p", [read_ec2]))
}

# --- Contournements corrigés : un test négatif par cas ----------------

test_not_action_refuse if {
	st := {"Effect": "Allow", "NotAction": ["iam:*"], "Resource": "*"}
	has_msg(deny, "NotAction") with input as state(apply_with("p", [st]))
}

test_not_resource_refuse if {
	st := {"Effect": "Allow", "Action": ["ec2:Describe*"], "NotResource": "arn:aws:ec2:*:*:*"}
	has_msg(deny, "NotResource") with input as state(apply_with("p", [st]))
}

test_policy_geree_aws_refusee if {
	res := [good_plan, good_apply, attachment("gha-terraform-apply", "arn:aws:iam::aws:policy/AdministratorAccess")]
	has_msg(deny, "non verifiable") with input as state(res)
}

test_policy_hors_prefixe_est_examinee if {
	# nom sans rapport avec « gha-terraform- » : seul l'attachement compte
	st := {"Effect": "Allow", "Action": ["*"], "Resource": "*"}
	res := [good_plan, good_apply, policy_res("nom-anodin", [st]), attachment("gha-terraform-apply", arn_of("nom-anodin"))]
	has_msg(deny, "joker de service entier") with input as state(res)
}

test_policy_inline_est_examinee if {
	st := {"Effect": "Allow", "Action": ["ec2:*"], "Resource": "*"}
	res := [good_plan, good_apply, inline_policy("gha-terraform-apply", [st])]
	has_msg(deny, "joker de service entier") with input as state(res)
}

test_policy_non_attachee_a_un_role_oidc_est_ignoree if {
	st := {"Effect": "Allow", "Action": ["*"], "Resource": "*"}
	res := [good_plan, good_apply, policy_res("orpheline", [st])]
	count(deny) == 0 with input as state(res)
}

test_joker_partiel_hors_lecture_refuse if {
	st := {"Effect": "Allow", "Action": ["ec2:Run*", "ec2:Delete*"], "Resource": "arn:aws:ec2:eu-west-3:*:*"}
	has_msg(deny, "joker partiel") with input as state(apply_with("p", [st]))
}

test_joker_partiel_de_lecture_accepte if {
	st := {"Effect": "Allow", "Action": ["ec2:Describe*", "s3:GetBucket*", "s3:List*"], "Resource": "*"}
	not has_msg(deny, "joker partiel") with input as state(apply_with("p", [st]))
}

test_managed_policy_arns_sur_le_role_refuse if {
	r := object.union(good_apply, {"values": {"name": "gha-terraform-apply", "assume_role_policy": good_apply.values.assume_role_policy, "managed_policy_arns": ["arn:aws:iam::aws:policy/ReadOnlyAccess"]}})
	has_msg(deny, "managed_policy_arns") with input as state([good_plan, r])
}

# --- Sub : égalité stricte et dépôt attendu fourni de l'extérieur -----

test_sub_avec_contexte_insere_refuse if {
	bad := role("gha-terraform-apply", trust(federated, "repo:acme/infra:ref:x:environment:production", "sts.amazonaws.com"))
	has_msg(deny, ":environment:production") with input as state([good_plan, bad])
}

test_depot_attendu_different_refuse if {
	has_msg(deny, "depot different") with input as state([good_plan, good_apply])
		with data.expected_repo as "autre-org/autre-repo"
}

test_depot_attendu_identique_accepte if {
	count(deny) == 0 with input as state([good_plan, good_apply])
		with data.expected_repo as "acme/infra"
}

test_aws_iam_policy_attachment_est_examine if {
	st := {"Effect": "Allow", "Action": ["ec2:*"], "Resource": "*"}
	att := {
		"type": "aws_iam_policy_attachment",
		"address": "aws_iam_policy_attachment.shared",
		"values": {"name": "shared", "roles": ["gha-terraform-apply"], "policy_arn": arn_of("p")},
	}
	res := [good_plan, good_apply, policy_res("p", [st]), att]
	has_msg(deny, "joker de service entier") with input as state(res)
}

# --- Règle 2 bis : opérateur du sub -----------------------------------

test_sub_avec_string_like_refuse if {
	doc := {"Version": "2012-10-17", "Statement": [{
		"Effect": "Allow",
		"Action": "sts:AssumeRoleWithWebIdentity",
		"Principal": federated,
		"Condition": {
			"StringEquals": {aud_key: "sts.amazonaws.com"},
			"StringLike": {sub_key: "repo:acme/infra:pull_request"},
		},
	}]}
	has_msg(deny, "utiliser StringEquals") with input as state([role("gha-terraform-plan", doc), good_apply])
}

test_sub_avec_string_equals_accepte if {
	not has_msg(deny, "utiliser StringEquals") with input as state([good_plan, good_apply])
}

# --- Sub « immuable » : repo:ORG@ID/REPO@ID (use_immutable_subject) ---------

immutable_plan := role("gha-terraform-plan", trust(federated, "repo:acme@111/infra@222:pull_request", "sts.amazonaws.com"))

immutable_apply := role("gha-terraform-apply", trust(federated, "repo:acme@111/infra@222:environment:production", "sts.amazonaws.com"))

test_sub_immuable_conforme_aucune_violation if {
	count(deny) == 0 with input as state([immutable_plan, immutable_apply])
}

test_sub_immuable_depot_attendu_identique_accepte if {
	count(deny) == 0 with input as state([immutable_plan, immutable_apply])
		with data.expected_repo as "acme@111/infra@222"
}

test_sub_classique_refuse_si_depot_attendu_immuable if {
	# le sub de la trust policy n'est pas celui que GitHub émettra : refus
	has_msg(deny, "depot different") with input as state([good_plan, good_apply])
		with data.expected_repo as "acme@111/infra@222"
}
