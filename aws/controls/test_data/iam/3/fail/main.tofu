resource "aws_iam_user_policy" "inline_policy" {
  user   = "example"
  policy = jsonencode({})
}

resource "aws_iam_user_policies_exclusive" "inline_policies_exclusive" {
  user_name    = "example"
  policy_names = ["example"]
}

resource "aws_iam_user_policy_attachment" "policy_attachment" {
  user       = "example"
  policy_arn = "arn:aws:iam::123456789012:policy/example"
}

resource "aws_iam_user_policy_attachments_exclusive" "exclusive_policy_attachment" {
  user_name   = "example"
  policy_arns = ["arn:aws:iam::123456789012:policy/example"]
}
