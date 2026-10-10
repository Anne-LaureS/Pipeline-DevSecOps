############################################
# OIDC — GitHub Actions -> AWS
# Aucun secret permanent : les rôles sont assumés
# via un jeton OIDC signé par GitHub, valable
# le temps du job uniquement.
############################################

variable "github_org" {
  description = "Organisation ou compte GitHub"
  type        = string
  default     = "VOTRE_ORG"
}

variable "github_repo" {
  description = "Nom du dépôt GitHub"
  type        = string
  default     = "VOTRE_REPO"
}

variable "aws_region" {
  description = "Région AWS dans laquelle les rôles ont le droit d'agir"
  type        = string
  default     = "eu-west-3"
}

variable "github_environment" {
  description = "Environment GitHub référencé par le job apply (environment: ...)"
  type        = string
  default     = "production"
}

# --- Fournisseur d'identité OIDC -----------------------------------------
# Le thumbprint ci-dessous est l'empreinte SHA-1 du dernier certificat de la
# chaîne servie par token.actions.githubusercontent.com (racine ISRG « Root YR »,
# Let's Encrypt), relevée le 2026-10-10 avec :
#   openssl s_client -connect token.actions.githubusercontent.com:443 -showcerts
# AWS valide aujourd'hui aussi via sa chaîne de confiance standard, mais on le
# garde explicite pour la traçabilité et parce que Terraform l'exige. À
# recalculer si GitHub change d'autorité.
resource "aws_iam_openid_connect_provider" "github_actions" {
  url = "https://token.actions.githubusercontent.com"

  client_id_list = [
    "sts.amazonaws.com"
  ]

  thumbprint_list = [
    "ab9d0263244dd0326eb67015705a667e79cfe998"
  ]
}

############################################
# Rôle 1 — gha-terraform-plan (lecture seule)
# Condition sub stricte : uniquement les événements
# pull_request de CE dépôt.
############################################

data "aws_iam_policy_document" "plan_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github_actions.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # --- Condition stricte (état normal) ---
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_org}/${var.github_repo}:pull_request"]
    }

    # --- TEST NÉGATIF (voir rapport, partie 1) ---
    # Pour le test, remplacer temporairement la condition ci-dessus par :
    #   values = ["repo:${var.github_org}/${var.github_repo}:*"]
    # puis "terraform apply", vérifier que get-caller-identity fonctionne
    # depuis N'IMPORTE QUEL contexte du dépôt (push, workflow_dispatch,
    # environment...), documenter le risque dans le rapport, puis
    # RÉTABLIR la ligne stricte ci-dessus et réappliquer avant de continuer.
  }
}

resource "aws_iam_role" "gha_terraform_plan" {
  name                 = "gha-terraform-plan"
  assume_role_policy   = data.aws_iam_policy_document.plan_trust.json
  max_session_duration = 3600 # 1h : durée de vie courte, cohérente avec un job CI
}

# Politique en lecture seule, limitée à ce que la stack gère réellement (EC2).
# Volontairement SANS s3:Get* (lirait le contenu de tous les objets),
# logs:Get* (lirait le contenu des journaux) ni iam:/rds: : à ajouter avec
# la ressource correspondante, jamais « au cas où ».
# sts:GetCallerIdentity n'a besoin d'aucune permission IAM.
data "aws_iam_policy_document" "plan_readonly" {
  statement {
    sid       = "ReadEc2"
    effect    = "Allow"
    actions   = ["ec2:Describe*"]
    resources = ["*"] # les actions Describe* ne se scopent pas par ARN

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = [var.aws_region]
    }
  }
}

resource "aws_iam_policy" "plan_readonly" {
  name   = "gha-terraform-plan-readonly"
  policy = data.aws_iam_policy_document.plan_readonly.json
}

resource "aws_iam_role_policy_attachment" "plan_readonly_attach" {
  role       = aws_iam_role.gha_terraform_plan.name
  policy_arn = aws_iam_policy.plan_readonly.arn
}

############################################
# Rôle 2 — gha-terraform-apply (écriture)
# Condition sub stricte : uniquement les jobs de CE dépôt
# qui référencent l'environment GitHub "production".
#
# Pourquoi l'environment et non ref:refs/heads/main : dès qu'un job
# déclare `environment:`, GitHub remplace le claim sub par
# repo:<ORG>/<REPO>:environment:<NOM> (le ref n'y figure plus). Une
# condition sur ref:refs/heads/main refuserait donc le job apply.
# Prérequis côté GitHub (Settings > Environments > production) :
# reviewers obligatoires ET "Deployment branches" limité à main, sinon
# n'importe quelle branche pourrait cibler cet environment.
############################################

data "aws_iam_policy_document" "apply_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github_actions.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_org}/${var.github_repo}:environment:${var.github_environment}"]
    }
  }
}

resource "aws_iam_role" "gha_terraform_apply" {
  name                 = "gha-terraform-apply"
  assume_role_policy   = data.aws_iam_policy_document.apply_trust.json
  max_session_duration = 3600
}

# Droits d'écriture limités à EC2 (Security Group + instance), dans UNE région.
# - lecture : Describe* (non scopable par ARN) ;
# - création : actions nommées une à une, ARN limités à la région ;
# - modification / suppression : uniquement sur les ressources étiquetées
#   ManagedBy=terraform (condition ec2:ResourceTag), donc jamais sur une
#   ressource créée hors Terraform.
# Pas de s3:*, rds:*, iam:PassRole : la stack n'en a pas besoin. Les ajouter
# avec la ressource qui les exige. NON testé sur un vrai compte AWS : valider
# avec IAM Access Analyzer (génération de policy depuis CloudTrail).
data "aws_iam_policy_document" "apply_write" {
  statement {
    sid       = "ReadEc2"
    effect    = "Allow"
    actions   = ["ec2:Describe*"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = [var.aws_region]
    }
  }

  statement {
    sid    = "CreateEc2"
    effect = "Allow"
    actions = [
      "ec2:RunInstances",
      "ec2:CreateSecurityGroup",
      "ec2:CreateTags",
    ]
    resources = ["arn:aws:ec2:${var.aws_region}:*:*"]
  }

  statement {
    sid    = "ManageTaggedEc2"
    effect = "Allow"
    actions = [
      "ec2:TerminateInstances",
      "ec2:StopInstances",
      "ec2:StartInstances",
      "ec2:ModifyInstanceAttribute",
      "ec2:ModifyInstanceMetadataOptions",
      "ec2:DeleteSecurityGroup",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:AuthorizeSecurityGroupEgress",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupEgress",
      "ec2:ModifySecurityGroupRules",
      "ec2:UpdateSecurityGroupRuleDescriptionsIngress",
      "ec2:UpdateSecurityGroupRuleDescriptionsEgress",
      "ec2:DeleteTags",
    ]
    resources = ["arn:aws:ec2:${var.aws_region}:*:*"]

    condition {
      test     = "StringEquals"
      variable = "ec2:ResourceTag/ManagedBy"
      values   = ["terraform"]
    }
  }
}

resource "aws_iam_policy" "apply_write" {
  name   = "gha-terraform-apply-write"
  policy = data.aws_iam_policy_document.apply_write.json
}

resource "aws_iam_role_policy_attachment" "apply_write_attach" {
  role       = aws_iam_role.gha_terraform_apply.name
  policy_arn = aws_iam_policy.apply_write.arn
}

output "plan_role_arn" {
  value = aws_iam_role.gha_terraform_plan.arn
}

output "apply_role_arn" {
  value = aws_iam_role.gha_terraform_apply.arn
}
