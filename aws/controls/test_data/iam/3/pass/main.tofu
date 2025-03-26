resource "aws_iam_user" "user" {
  name = "example"
}

resource "aws_iam_group" "group" {
  name = "example"
}

resource "aws_iam_group_policy_attachment" "attachment" {
  group      = aws_iam_group.group.name
  policy_arn = "arn:aws:iam::123456789012:policy/example"
}

resource "aws_iam_user_group_membership" "group_membership" {
  user   = aws_iam_user.user.name
  groups = [aws_iam_group.group.name]
}
