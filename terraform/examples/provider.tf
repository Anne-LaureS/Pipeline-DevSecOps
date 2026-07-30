terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Identifiants factices : LocalStack les accepte tels quels, ils ne
# donnent accès à rien de réel. Ne JAMAIS utiliser ce pattern contre
# un vrai compte AWS.
provider "aws" {
  region                      = "eu-west-3"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true

  endpoints {
    ec2 = "http://localhost:4566"
    iam = "http://localhost:4566"
    sts = "http://localhost:4566"
    s3  = "http://localhost:4566"
  }
}
