resource "aws_lambda_permission" "account_principal" {
  function_name = "lambda"
  action        = "lambda:InvokeFunction"
  principal     = "123456789012"
}

resource "aws_lambda_permission" "iam_principal" {
  function_name = "lambda"
  action        = "lambda:InvokeFunction"
  principal     = "arn:aws:iam::123456789012:role/example"
}

resource "aws_lambda_permission" "function_url_auth" {
  function_name          = "lambda"
  action                 = "lambda:InvokeFunctionUrl"
  principal              = "*"
  function_url_auth_type = "AWS_IAM"
}

resource "aws_lambda_permission" "source_account" {
  function_name  = "lambda"
  action         = "lambda:InvokeFunction"
  source_account = "123456789012"
  principal      = each.value
  for_each       = toset(["*", "sns.amazonaws.com"])
}

resource "aws_lambda_permission" "source_arn" {
  function_name = "lambda"
  action        = "lambda:InvokeFunction"
  source_arn    = "arn:aws:s3:::example"
  principal     = each.value
  for_each      = toset(["*", "sns.amazonaws.com"])
}

resource "aws_lambda_permission" "source_org" {
  function_name    = "lambda"
  action           = "lambda:InvokeFunction"
  principal_org_id = "o-a1b2c3d4e5f"
  principal        = each.value
  for_each         = toset(["*", "sns.amazonaws.com"])
}
