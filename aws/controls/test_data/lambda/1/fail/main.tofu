resource "aws_lambda_permission" "function_auth_none" {
  function_name          = "lambda"
  action                 = "lambda:InvokeFunctionUrl"
  principal              = "123456789012"
  function_url_auth_type = "NONE"
}

resource "aws_lambda_permission" "missing_source" {
  function_name = "lambda"
  action        = "lambda:InvokeFunction"
  principal     = "*"
}

resource "aws_lambda_permission" "empty_source" {
  function_name = "lambda"
  action        = "lambda:InvokeFunction"
  principal     = "sns.amazonaws.com"
  source_arn    = ""
  # source_account is checked by the provider
  principal_org_id = ""
}
