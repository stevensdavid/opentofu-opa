locals {
  policies = toset([
    jsonencode({
      Version = "20212-10-17",
      Statement = [
        {
          Effect   = "Allow",
          Action   = "*"
          Resource = "*"
    }] }),
    jsonencode({
      Version = "20212-10-17",
      Statement = [
        {
          Effect   = "Allow",
          Action   = ["*"]
          Resource = ["*"]
    }] }),
  ])
}

resource "aws_iam_policy" "invalid" {
  policy   = each.value
  for_each = local.policies
}

resource "aws_iam_role" "invalid" {
  assume_role_policy = "{}"
  inline_policy {
    policy = each.value
  }
  for_each = local.policies
}

resource "aws_iam_user_policy" "invalid" {
  user     = "example"
  policy   = each.value
  for_each = local.policies
}

resource "aws_iam_group_policy" "invalid" {
  group    = "example"
  policy   = each.value
  for_each = local.policies
}

resource "aws_iam_role_policy" "invalid" {
  role     = "example"
  policy   = each.value
  for_each = local.policies
}

data "aws_iam_policy_document" "admin" {
  statement {
    effect    = "Allow"
    resources = ["*"]
    actions   = ["*"]
  }
}
