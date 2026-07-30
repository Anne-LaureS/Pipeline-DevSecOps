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

# --- Fournisseur d'identité OIDC -----------------------------------------
# Le thumbprint ci-dessous est celui de l'autorité racine utilisée par
# token.actions.githubusercontent.com au moment de la rédaction. AWS valide
# aujourd'hui aussi via la chaîne de confiance standard, mais on le garde
# explicite pour la traçabilité et parce que Terraform l'exige.
resource "aws_iam_openid_connect_provider" "github_actions" {
  url = "https://token.actions.githubusercontent.com"

  client_id_list = [
    "sts.amazonaws.com"
  ]

  thumbprint_list = [
    "6938fd4d98bab03faadb97b34396831e3780aea"
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

    # --- TEST NÉGATIF (partie A, point 3) ---
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

# Politique en lecture seule restreinte : ReadOnlyAccess est volontairement
# large ; ici on préfère une politique dédiée limitée aux services réellement
# utilisés (à adapter à votre stack). Remplacez par ReadOnlyAccess si votre
# stack est trop hétérogène pour justifier une liste explicite.
data "aws_iam_policy_document" "plan_readonly" {
  statement {
    sid    = "ReadOnlyScoped"
    effect = "Allow"
    actions = [
      "ec2:Describe*",
      "iam:Get*",
      "iam:List*",
      "s3:Get*",
      "s3:List*",
      "rds:Describe*",
      "logs:Describe*",
      "logs:Get*",
      "sts:GetCallerIdentity"
    ]
    resources = ["*"]
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
# Condition sub stricte : uniquement les push
# sur la branche main de CE dépôt.
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
      values   = ["repo:${var.github_org}/${var.github_repo}:ref:refs/heads/main"]
    }
  }
}

resource "aws_iam_role" "gha_terraform_apply" {
  name                 = "gha-terraform-apply"
  assume_role_policy   = data.aws_iam_policy_document.apply_trust.json
  max_session_duration = 3600
}

# Droits d'écriture limités aux services utilisés (exemple : EC2 + S3 + IAM
# scoping restreint). À adapter précisément à votre TF state.
data "aws_iam_policy_document" "apply_write" {
  statement {
    sid    = "WriteScoped"
    effect = "Allow"
    actions = [
      "ec2:*",
      "s3:*",
      "rds:CreateDBInstance",
      "rds:ModifyDBInstance",
      "rds:DeleteDBInstance",
      "rds:Describe*",
      "iam:PassRole"
    ]
    resources = ["*"]
    # NB : dans un vrai rendu, restreindre "resources" par ARN/tag plutôt
    # que "*" — assumé comme risque résiduel si non fait (cf. partie D).
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
