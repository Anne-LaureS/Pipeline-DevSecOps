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
  ami           = "ami-0c55b159cbfafe1f0" # AMI factice, LocalStack ne vérifie pas son existence réelle
  instance_type = "t3.micro"

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required" # ### VIOLATION règle 2 : mettre "optional" pour tester

  }

  root_block_device {
    encrypted = true # ### VIOLATION règle 3 : mettre "false" pour tester
  }

  tags = {
    Environment = "staging"
    Owner       = "equipe-cybersec"
    ManagedBy   = "terraform"
    # ### VIOLATION règle 4 : commenter une ou plusieurs des 3 lignes
    # ci-dessus (Environment / Owner / ManagedBy) pour tester
  }
}
