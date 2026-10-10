package main

import rego.v1

# Ce fichier est évalué par conftest contre le JSON produit par
# `terraform show -json tfplan.binary`. On y parcourt
# input.resource_changes, qui contient toutes les ressources créées
# ou modifiées par le plan.
#
# Principe de conception : une valeur INCONNUE ou ABSENTE au plan n'est jamais
# prise pour conforme. Terraform omet de `after` les valeurs calculées à
# l'apply (elles figurent dans `after_unknown`) : une règle qui compare une
# valeur absente ne se déclencherait pas. Ces règles refusent donc ce qu'elles
# ne peuvent pas vérifier (fail closed).
#
# Syntaxe Rego v1 (OPA >= 1.0 / conftest >= 0.5x) : les règles
# à ensemble partiel utilisent `contains ... if { ... }`.

# --- Helpers ---------------------------------------------------------

is_create_or_update(rc) if {
	"create" in rc.change.actions
}

is_create_or_update(rc) if {
	"update" in rc.change.actions
}

# Liste de blocs d'un attribut ; vide si l'attribut est absent ou null
# (cas d'un bloc omis ou calculé à l'apply).
as_list(x) := x if is_array(x)

as_list(x) := [] if not is_array(x)

blocks(after, key) := as_list(object.get(after, key, []))

# --- Helpers réseau ----------------------------------------------------

public_cidrs := {"0.0.0.0/0", "::/0"}

# Tous les CIDR d'une règle, quel que soit le type de ressource :
# cidr_blocks / ipv6_cidr_blocks (security group, security group rule) et
# cidr_ipv4 / cidr_ipv6 (aws_vpc_security_group_ingress_rule).
cidr_values(rule) := {c |
	some k in ["cidr_blocks", "ipv6_cidr_blocks"]
	some c in as_list(object.get(rule, k, []))
} | {c |
	some k in ["cidr_ipv4", "cidr_ipv6"]
	c := object.get(rule, k, null)
	c != null
}

public_targets(rule) := cidr_values(rule) & public_cidrs

# Protocole : `protocol` (security group, rule) ou `ip_protocol` (vpc rule).
protocol_of(rule) := lower(p) if {
	p := object.get(rule, "protocol", object.get(rule, "ip_protocol", ""))
	is_string(p)
}

# "-1" (tout protocole) : les ports valent 0 et ne disent rien, mais SSH est
# ouvert avec tout le reste.
all_traffic(rule) if protocol_of(rule) in {"-1", "all"}

ssh_port_in_range(rule) if {
	protocol_of(rule) in {"tcp", "6"}
	rule.from_port <= 22
	rule.to_port >= 22
}

exposes_ssh(rule) if all_traffic(rule)

exposes_ssh(rule) if ssh_port_in_range(rule)

ssh_msg(kind, address, rule, target) := sprintf(
	"SECURITE: %s '%s' ouvre le port SSH (22) a %s (acces public non autorise)",
	[kind, address, target],
) if not all_traffic(rule)

ssh_msg(kind, address, rule, target) := sprintf(
	"SECURITE: %s '%s' ouvre tout le trafic (protocole %s, dont SSH 22) a %s (acces public non autorise)",
	[kind, address, protocol_of(rule), target],
) if all_traffic(rule)

# ======================================================================
# Règle 1 — Refus de SSH (port 22) ouvert sur Internet (0.0.0.0/0 ou ::/0)
# Couvre aws_security_group (ingress inline), aws_security_group_rule et
# aws_vpc_security_group_ingress_rule, en IPv4 et IPv6, y compris
# protocole « -1 » (tout le trafic).
# ======================================================================

deny contains msg if {
	rc := input.resource_changes[_]
	rc.type == "aws_security_group"
	is_create_or_update(rc)
	ingress := blocks(rc.change.after, "ingress")[_]
	exposes_ssh(ingress)
	some target in public_targets(ingress)
	msg := ssh_msg("le security group", rc.address, ingress, target)
}

deny contains msg if {
	rc := input.resource_changes[_]
	rc.type == "aws_security_group_rule"
	is_create_or_update(rc)
	after := rc.change.after
	after.type == "ingress"
	exposes_ssh(after)
	some target in public_targets(after)
	msg := ssh_msg("la regle", rc.address, after, target)
}

deny contains msg if {
	rc := input.resource_changes[_]
	rc.type == "aws_vpc_security_group_ingress_rule"
	is_create_or_update(rc)
	after := rc.change.after
	exposes_ssh(after)
	some target in public_targets(after)
	msg := ssh_msg("la regle", rc.address, after, target)
}

# ======================================================================
# Règle 2 — http_tokens = "required" obligatoire (IMDSv2)
# La valeur doit être fixée explicitement : absente ou inconnue au plan,
# elle n'est pas garantie.
# ======================================================================

deny contains msg if {
	rc := input.resource_changes[_]
	rc.type == "aws_instance"
	is_create_or_update(rc)
	mo := blocks(rc.change.after, "metadata_options")[_]
	t := object.get(mo, "http_tokens", null)
	t != null
	t != "required"
	msg := sprintf(
		"SECURITE: l'instance '%s' n'impose pas IMDSv2 (http_tokens doit valoir 'required')",
		[rc.address],
	)
}

deny contains msg if {
	rc := input.resource_changes[_]
	rc.type == "aws_instance"
	is_create_or_update(rc)
	count(blocks(rc.change.after, "metadata_options")) == 0
	msg := sprintf(
		"SECURITE: l'instance '%s' ne definit aucun bloc metadata_options (IMDSv2 non force)",
		[rc.address],
	)
}

deny contains msg if {
	rc := input.resource_changes[_]
	rc.type == "aws_instance"
	is_create_or_update(rc)
	mo := blocks(rc.change.after, "metadata_options")[_]
	object.get(mo, "http_tokens", null) == null
	msg := sprintf(
		"SECURITE: l'instance '%s' ne fixe pas http_tokens explicitement (IMDSv2 non garanti, valeur inconnue au plan)",
		[rc.address],
	)
}

# ======================================================================
# Règle 3 — Chiffrement des disques obligatoire
# Disque racine, disques supplémentaires (ebs_block_device) et volumes EBS.
# ======================================================================

deny contains msg if {
	rc := input.resource_changes[_]
	rc.type == "aws_instance"
	is_create_or_update(rc)
	root_bd := blocks(rc.change.after, "root_block_device")[_]
	e := object.get(root_bd, "encrypted", null)
	e != null
	e != true
	msg := sprintf(
		"SECURITE: le disque racine de l'instance '%s' n'est pas chiffre (encrypted doit valoir true)",
		[rc.address],
	)
}

deny contains msg if {
	rc := input.resource_changes[_]
	rc.type == "aws_instance"
	is_create_or_update(rc)
	count(blocks(rc.change.after, "root_block_device")) == 0
	msg := sprintf(
		"SECURITE: l'instance '%s' ne definit aucun root_block_device (chiffrement du disque racine non garanti)",
		[rc.address],
	)
}

deny contains msg if {
	rc := input.resource_changes[_]
	rc.type == "aws_instance"
	is_create_or_update(rc)
	root_bd := blocks(rc.change.after, "root_block_device")[_]
	object.get(root_bd, "encrypted", null) == null
	msg := sprintf(
		"SECURITE: le disque racine de l'instance '%s' ne fixe pas encrypted (valeur inconnue au plan, chiffrement non garanti)",
		[rc.address],
	)
}

deny contains msg if {
	rc := input.resource_changes[_]
	rc.type == "aws_instance"
	is_create_or_update(rc)
	bd := blocks(rc.change.after, "ebs_block_device")[_]
	object.get(bd, "encrypted", null) != true
	msg := sprintf(
		"SECURITE: un disque supplementaire (ebs_block_device) de l'instance '%s' n'est pas chiffre (encrypted doit valoir true)",
		[rc.address],
	)
}

deny contains msg if {
	rc := input.resource_changes[_]
	rc.type == "aws_ebs_volume"
	is_create_or_update(rc)
	object.get(rc.change.after, "encrypted", null) != true
	msg := sprintf(
		"SECURITE: le volume EBS '%s' n'est pas chiffre (encrypted doit valoir true)",
		[rc.address],
	)
}

# ======================================================================
# Règle 4 — Étiquettes obligatoires : Environment, Owner, ManagedBy
# ======================================================================

required_tags := {"Environment", "Owner", "ManagedBy"}

taggable_types := {"aws_instance", "aws_security_group", "aws_ebs_volume"}

deny contains msg if {
	rc := input.resource_changes[_]
	is_create_or_update(rc)
	tags := object.get(rc.change.after, "tags", null)
	tags != null
	missing := required_tags - object.keys(tags)
	count(missing) > 0
	msg := sprintf(
		"SECURITE: la ressource '%s' n'a pas les etiquettes obligatoires : %v",
		[rc.address, missing],
	)
}

deny contains msg if {
	rc := input.resource_changes[_]
	is_create_or_update(rc)
	rc.type in taggable_types
	object.get(rc.change.after, "tags", null) == null
	msg := sprintf(
		"SECURITE: la ressource '%s' n'a aucune etiquette (tags requis : Environment, Owner, ManagedBy)",
		[rc.address],
	)
}
