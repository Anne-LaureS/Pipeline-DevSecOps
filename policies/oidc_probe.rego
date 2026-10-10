package oidc_probe

import data.oidc_sim
import rego.v1

# Sorties destinées au test différentiel avec un second moteur (OpenBao) :
#   scripts/openbao-oidc-check.sh
# Ce fichier ne contient aucune règle de refus : seulement des « warn » lus par
# le script, uniquement quand on évalue le namespace `oidc_probe`. Il ne
# modifie donc ni les résultats ni les compteurs des autres namespaces.
#
#   conftest test state.json --policy policies --namespace oidc_probe \
#     --data <dossier> --output json
# où <dossier> peut contenir {"expected_repo": "..."} et {"probes": [{"sub","aud"}]}.

# Paires (sub|aud) des scénarios de la simulation : les jetons à signer.
warn_scenarios contains msg if {
	some _, sc in oidc_sim.scenarios
	msg := sprintf("%s|%s", [sc.sub, sc.aud])
}

# Décision de la simulation pour chaque jeton fourni et chaque rôle du state.
warn_decisions contains msg if {
	some p in data.probes
	some name, r in oidc_sim.roles_by_name
	decision := oidc_sim.decision(r, oidc_sim.token(p.sub, p.aud))
	msg := sprintf("%s|%s|%s|%s", [name, p.sub, p.aud, oidc_sim.label(decision)])
}
