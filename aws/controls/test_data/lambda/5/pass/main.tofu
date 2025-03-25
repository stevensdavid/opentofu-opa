resource "aws_lambda_function_url" "valid" {
  function_name      = "example"
  authorization_type = "AWS_IAM"
  cors {
    allow_origins = ["example.com"]
  }
}
