# Ressources d'exemple, appliquées contre LocalStack, servant à générer
# un plan JSON que conftest vérifie contre policies/securite.rego.
#
# Cet état (ci-dessous) est CONFORME aux 4 règles. Pour le test négatif
# obligatoire (partie C, point 3), commentez/décommentez un bloc à la
# fois indiqué "### VIOLATION", relancez `terraform plan` + `conftest
# test`, capturez le message de refus, puis remettez la version
# conforme avant de passer à la règle suivante.

resource "aws_security_group" "demo" {
  name        = "demo-sg"
  description = "Security group de démonstration"

  ingress {
    description = "HTTPS depuis Internet (autorise)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Environment = "staging"
    Owner       = "equipe-cybersec"
    ManagedBy   = "terraform"
  }
}

resource "aws_instance" "demo" {
  # AMI réellement enregistrée dans le catalogue simulé (moto) de LocalStack
  # Community — vérifié par appel direct à DescribeImages en local. Les AMI
  # "pré-téléchargées" documentées par LocalStack (ami-df5de72bdb3b...)
  # appartiennent au moteur EC2 "Docker" de la version Pro (vrais conteneurs
  # taggés comme AMI) et n'existent pas ici : d'où l'échec précédent,
  # confirmé en reproduisant l'apply en local contre le même LocalStack:4.4.0
  # (log serveur : "ec2.DescribeImages => 400 InvalidAMIID.NotFound").
  ami           = "ami-760aaa0f" # amzn-ami-hvm-2017.09.1.20171103-x86_64-gp2
  instance_type = "t3.micro"

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required" # ### VIOLATION règle 2 : mettre "optional" pour tester

  }

  root_block_device {
    # volume_size explicite : requis par l'émulation EC2 de LocalStack pour
    # finaliser correctement le volume racine, sinon la relecture de
    # l'instance après création échoue ("couldn't find resource" — bug connu
    # LocalStack/localstack#6062, sans lien avec la conformité de sécurité).
    volume_size = 8
    encrypted   = true # ### VIOLATION règle 3 : mettre "false" pour tester
  }

  tags = {
    Environment = "staging"
    Owner       = "equipe-cybersec"
    ManagedBy   = "terraform"
    # ### VIOLATION règle 4 : commenter une ou plusieurs des 3 lignes
    # ci-dessus (Environment / Owner / ManagedBy) pour tester
  }
}

# Sorties affichées en fin d'apply — utile pour la démo live (scripts/demo-local.sh),
# aucun outil supplémentaire requis pour prouver que les ressources existent.
output "instance_id" {
  value = aws_instance.demo.id
}

output "security_group_id" {
  value = aws_security_group.demo.id
}
