locals {
  policies = toset([
    jsonencode({
      Version = "20212-10-17",
      Statement = [
        {
          Effect   = "Deny",
          Action   = "s3:*"
          Resource = "*"
    }] }),
    jsonencode({
      Version = "20212-10-17",
      Statement = [{
        Effect    = "Deny"
        Resource  = "*"
        NotAction = "s3:GetObject"
    }] }),
    jsonencode({
      Version = "20212-10-17",
      Statement = [{
        Effect   = "Allow"
        Resource = "*"
        Action   = "s3:GetObject"
    }] }),
  ])
}

resource "aws_iam_policy" "valid" {
  policy   = each.value
  for_each = local.policies
}

resource "aws_iam_role" "valid" {
  assume_role_policy = "{}"
  inline_policy {
    policy = each.value
  }
  for_each = local.policies
}

resource "aws_iam_user_policy" "valid" {
  user     = "example"
  policy   = each.value
  for_each = local.policies
}

resource "aws_iam_group_policy" "valid" {
  group    = "example"
  policy   = each.value
  for_each = local.policies
}

resource "aws_iam_role_policy" "valid" {
  role     = "example"
  policy   = each.value
  for_each = local.policies
}

data "aws_iam_policy_document" "valid" {
  statement {
    effect    = "Allow"
    resources = ["*"]
    actions   = ["s3:GetObject"]
  }
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["*"]
  }
  statement {
    effect      = "Deny"
    not_actions = ["s3:GetObject"]
    resources   = ["*"]
  }
}
