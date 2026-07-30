package main

import rego.v1

# Ce fichier est évalué par conftest contre le JSON produit par
# `terraform show -json tfplan.binary`. On y parcourt
# input.resource_changes, qui contient toutes les ressources créées
# ou modifiées par le plan.
#
# Syntaxe Rego v1 (OPA >= 1.0 / conftest >= 0.5x) : les règles
# à ensemble partiel utilisent `contains ... if { ... }`.

# --- Helpers ---------------------------------------------------------

is_create_or_update(rc) if {
	rc.change.actions[_] == "create"
}

is_create_or_update(rc) if {
	rc.change.actions[_] == "update"
}

# ======================================================================
# Règle 1 — Refus de SSH (port 22) ouvert sur 0.0.0.0/0
# Couvre aws_security_group (ingress inline) et aws_security_group_rule
# ======================================================================

deny contains msg if {
	rc := input.resource_changes[_]
	rc.type == "aws_security_group"
	is_create_or_update(rc)
	ingress := rc.change.after.ingress[_]
	ingress.from_port <= 22
	ingress.to_port >= 22
	cidr := ingress.cidr_blocks[_]
	cidr == "0.0.0.0/0"
	msg := sprintf(
		"SECURITE: le security group '%s' ouvre le port SSH (22) a 0.0.0.0/0 (acces public non autorise)",
		[rc.address],
	)
}

deny contains msg if {
	rc := input.resource_changes[_]
	rc.type == "aws_security_group_rule"
	is_create_or_update(rc)
	after := rc.change.after
	after.type == "ingress"
	after.from_port <= 22
	after.to_port >= 22
	cidr := after.cidr_blocks[_]
	cidr == "0.0.0.0/0"
	msg := sprintf(
		"SECURITE: la regle '%s' ouvre le port SSH (22) a 0.0.0.0/0 (acces public non autorise)",
		[rc.address],
	)
}

# ======================================================================
# Règle 2 — http_tokens = "required" obligatoire (IMDSv2)
# ======================================================================

deny contains msg if {
	rc := input.resource_changes[_]
	rc.type == "aws_instance"
	is_create_or_update(rc)
	after := rc.change.after
	metadata_opts := after.metadata_options[_]
	metadata_opts.http_tokens != "required"
	msg := sprintf(
		"SECURITE: l'instance '%s' n'impose pas IMDSv2 (http_tokens doit valoir 'required')",
		[rc.address],
	)
}

deny contains msg if {
	rc := input.resource_changes[_]
	rc.type == "aws_instance"
	is_create_or_update(rc)
	after := rc.change.after
	count(after.metadata_options) == 0
	msg := sprintf(
		"SECURITE: l'instance '%s' ne definit aucun bloc metadata_options (IMDSv2 non force)",
		[rc.address],
	)
}

# ======================================================================
# Règle 3 — Chiffrement du disque racine obligatoire
# ======================================================================

deny contains msg if {
	rc := input.resource_changes[_]
	rc.type == "aws_instance"
	is_create_or_update(rc)
	after := rc.change.after
	root_bd := after.root_block_device[_]
	root_bd.encrypted != true
	msg := sprintf(
		"SECURITE: le disque racine de l'instance '%s' n'est pas chiffre (encrypted doit valoir true)",
		[rc.address],
	)
}

deny contains msg if {
	rc := input.resource_changes[_]
	rc.type == "aws_ebs_volume"
	is_create_or_update(rc)
	after := rc.change.after
	after.encrypted != true
	msg := sprintf(
		"SECURITE: le volume EBS '%s' n'est pas chiffre (encrypted doit valoir true)",
		[rc.address],
	)
}

# ======================================================================
# Règle 4 — Étiquettes obligatoires : Environment, Owner, ManagedBy
# ======================================================================

required_tags := {"Environment", "Owner", "ManagedBy"}

deny contains msg if {
	rc := input.resource_changes[_]
	is_create_or_update(rc)
	after := rc.change.after
	after.tags != null
	missing := required_tags - {k | after.tags[k]}
	count(missing) > 0
	msg := sprintf(
		"SECURITE: la ressource '%s' n'a pas les etiquettes obligatoires : %v",
		[rc.address, missing],
	)
}

deny contains msg if {
	rc := input.resource_changes[_]
	is_create_or_update(rc)
	after := rc.change.after
	after.tags == null
	rc.type == "aws_instance"
	msg := sprintf(
		"SECURITE: la ressource '%s' n'a aucune etiquette (tags requis : Environment, Owner, ManagedBy)",
		[rc.address],
	)
}
