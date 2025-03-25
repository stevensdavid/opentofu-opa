resource "aws_lambda_function_url" "invalid" {
  authorization_type = "NONE"
  function_name      = "example"
}
