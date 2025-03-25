resource "aws_lambda_function_url" "valid" {
  authorization_type = "AWS_IAM"
  function_name      = "example"
}
