locals {
  policies = toset([
    jsonencode({
      Version = "20212-10-17",
      Statement = [
        {
          Effect = "Allow",
          Action = "*"
          # no resource specified, so this is fine
    }] }),
    jsonencode({
      Version = "20212-10-17",
      Statement = [{
        Effect   = "Allow"
        Resource = "*"
        # no action specified, so this is fine
    }] }),
    jsonencode({
      Version = "20212-10-17",
      Statement = [{
        Effect   = "Allow"
        Resource = "*",
        Action   = "s3:GetObject"
    }] }),
    jsonencode({
      Version = "20212-10-17",
      Statement = [{
        Effect   = "Allow"
        Resource = "arn:aws:s3:::example",
        Action   = "*"
    }] }),
    jsonencode({
      Version = "20212-10-17",
      Statement = [{
        Effect   = "Deny"
        Action   = "*"
        Resource = "*"
    }] }),
    jsonencode({
      Version = "20212-10-17",
      Statement = [{
        Effect   = "Allow"
        Action   = "s3:*"
        Resource = "arn:aws:s3:::example/*"
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
  }
  statement {
    effect  = "Allow"
    actions = ["*"]
  }
  statement {
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]
  }
  statement {
    effect    = "Allow"
    actions   = ["*"]
    resources = ["arn:aws:s3:::example"]
  }
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
  statement {
    effect    = "Allow"
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::example/*"]
  }
}
