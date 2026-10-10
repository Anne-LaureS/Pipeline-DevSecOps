package main

import rego.v1

# Tests unitaires de securite.rego : `conftest verify --policy policies`
# (aucun plan réel nécessaire : les fixtures sont construites ici).
# Un cas conforme, puis au moins un cas négatif par contournement connu.

ok_tags := {"Environment": "staging", "Owner": "equipe", "ManagedBy": "terraform"}

rc(type, after) := {
	"address": sprintf("%s.t", [type]),
	"type": type,
	"change": {"actions": ["create"], "after": after, "after_unknown": {}},
}

plan(resources) := {"resource_changes": resources}

has_msg(needle) if {
	some m in deny
	contains(m, needle)
}

sg(ingress) := rc("aws_security_group", {"name": "sg", "tags": ok_tags, "ingress": ingress})

tcp(from_port, to_port, cidrs) := {
	"from_port": from_port,
	"to_port": to_port,
	"protocol": "tcp",
	"cidr_blocks": cidrs,
	"ipv6_cidr_blocks": [],
}

instance(after) := rc("aws_instance", object.union(
	{
		"ami": "ami-1",
		"tags": ok_tags,
		"metadata_options": [{"http_endpoint": "enabled", "http_tokens": "required"}],
		"root_block_device": [{"encrypted": true, "volume_size": 8}],
	},
	after,
))

# --- Témoin conforme --------------------------------------------------

test_configuration_conforme_aucune_violation if {
	res := [
		sg([tcp(443, 443, ["0.0.0.0/0"])]),
		instance({}),
		rc("aws_ebs_volume", {"size": 8, "encrypted": true, "tags": ok_tags}),
	]
	count(deny) == 0 with input as plan(res)
}

# --- Règle 1 : SSH ouvert ---------------------------------------------

test_ssh_ipv4_refuse if {
	has_msg("ouvre le port SSH (22) a 0.0.0.0/0") with input as plan([sg([tcp(22, 22, ["0.0.0.0/0"])])])
}

test_ssh_plage_incluant_22_refuse if {
	has_msg("ouvre le port SSH (22)") with input as plan([sg([tcp(0, 65535, ["0.0.0.0/0"])])])
}

test_ssh_ipv6_refuse if {
	ing := {"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": [], "ipv6_cidr_blocks": ["::/0"]}
	has_msg("a ::/0") with input as plan([sg([ing])])
}

test_tout_le_trafic_protocole_moins1_refuse if {
	# from_port / to_port valent 0 avec le protocole -1 : l'ancienne règle
	# (to_port >= 22) ne le voyait pas.
	ing := {"from_port": 0, "to_port": 0, "protocol": "-1", "cidr_blocks": ["0.0.0.0/0"], "ipv6_cidr_blocks": []}
	has_msg("ouvre tout le trafic") with input as plan([sg([ing])])
}

test_tout_le_trafic_ipv6_refuse if {
	ing := {"from_port": 0, "to_port": 0, "protocol": "-1", "cidr_blocks": [], "ipv6_cidr_blocks": ["::/0"]}
	has_msg("ouvre tout le trafic") with input as plan([sg([ing])])
}

test_security_group_rule_protocole_moins1_refuse if {
	r := rc("aws_security_group_rule", {"type": "ingress", "from_port": 0, "to_port": 0, "protocol": "-1", "cidr_blocks": ["0.0.0.0/0"]})
	has_msg("ouvre tout le trafic") with input as plan([r])
}

test_security_group_rule_ssh_refuse if {
	r := rc("aws_security_group_rule", {"type": "ingress", "from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]})
	has_msg("ouvre le port SSH (22)") with input as plan([r])
}

test_vpc_ingress_rule_ssh_ipv4_refuse if {
	r := rc("aws_vpc_security_group_ingress_rule", {"cidr_ipv4": "0.0.0.0/0", "from_port": 22, "to_port": 22, "ip_protocol": "tcp", "tags": ok_tags})
	has_msg("ouvre le port SSH (22) a 0.0.0.0/0") with input as plan([r])
}

test_vpc_ingress_rule_ssh_ipv6_refuse if {
	r := rc("aws_vpc_security_group_ingress_rule", {"cidr_ipv6": "::/0", "from_port": 22, "to_port": 22, "ip_protocol": "tcp", "tags": ok_tags})
	has_msg("a ::/0") with input as plan([r])
}

test_vpc_ingress_rule_tout_le_trafic_refuse if {
	r := rc("aws_vpc_security_group_ingress_rule", {"cidr_ipv4": "0.0.0.0/0", "ip_protocol": "-1", "tags": ok_tags})
	has_msg("ouvre tout le trafic") with input as plan([r])
}

test_ssh_restreint_a_un_reseau_prive_accepte if {
	not has_msg("SSH") with input as plan([sg([tcp(22, 22, ["10.0.0.0/8"])])])
}

test_https_public_accepte if {
	not has_msg("SSH") with input as plan([sg([tcp(443, 443, ["0.0.0.0/0"])])])
}

# --- Règle 2 : IMDSv2 ------------------------------------------------

test_imds_optional_refuse if {
	i := instance({"metadata_options": [{"http_tokens": "optional"}]})
	has_msg("n'impose pas IMDSv2") with input as plan([i])
}

test_imds_bloc_absent_refuse if {
	i := instance({"metadata_options": []})
	has_msg("aucun bloc metadata_options") with input as plan([i])
}

test_imds_http_tokens_inconnu_refuse if {
	# bloc présent mais http_tokens calculé à l'apply : absent de `after`
	i := instance({"metadata_options": [{"http_endpoint": "enabled"}]})
	has_msg("ne fixe pas http_tokens explicitement") with input as plan([i])
}

# --- Règle 3 : chiffrement -------------------------------------------

test_disque_racine_non_chiffre_refuse if {
	i := instance({"root_block_device": [{"encrypted": false, "volume_size": 8}]})
	has_msg("disque racine") with input as plan([i])
}

test_chiffrement_inconnu_refuse if {
	i := instance({"root_block_device": [{"volume_size": 8}]})
	has_msg("ne fixe pas encrypted") with input as plan([i])
}

test_instance_sans_root_block_device_refusee if {
	i := instance({"root_block_device": []})
	has_msg("ne definit aucun root_block_device") with input as plan([i])
}

test_disque_supplementaire_non_chiffre_refuse if {
	i := instance({"ebs_block_device": [{"device_name": "/dev/sdf", "encrypted": false}]})
	has_msg("ebs_block_device") with input as plan([i])
}

test_volume_ebs_non_chiffre_refuse if {
	v := rc("aws_ebs_volume", {"size": 8, "encrypted": false, "tags": ok_tags})
	has_msg("volume EBS") with input as plan([v])
}

test_volume_ebs_chiffrement_inconnu_refuse if {
	v := rc("aws_ebs_volume", {"size": 8, "tags": ok_tags})
	has_msg("volume EBS") with input as plan([v])
}

# --- Règle 4 : étiquettes --------------------------------------------

test_tag_owner_manquant_refuse if {
	# fixture explicite : object.union fusionnerait les tags avec ceux du témoin
	i := rc("aws_instance", {
		"ami": "ami-1",
		"tags": {"Environment": "staging", "ManagedBy": "terraform"},
		"metadata_options": [{"http_tokens": "required"}],
		"root_block_device": [{"encrypted": true}],
	})
	has_msg("etiquettes obligatoires") with input as plan([i])
}

test_instance_sans_tags_refusee if {
	i := instance({"tags": null})
	has_msg("aucune etiquette") with input as plan([i])
}

test_security_group_sans_tags_refuse if {
	s := rc("aws_security_group", {"name": "sg", "ingress": []})
	has_msg("aucune etiquette") with input as plan([s])
}

# --- Ressources supprimées : ignorées --------------------------------

test_ressource_supprimee_ignoree if {
	r := {
		"address": "aws_security_group.old",
		"type": "aws_security_group",
		"change": {"actions": ["delete"], "after": null, "after_unknown": {}},
	}
	count(deny) == 0 with input as plan([r])
}
