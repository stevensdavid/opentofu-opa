resource "aws_lambda_function_url" "valid" {
  function_name      = "example"
  authorization_type = "AWS_IAM"
  cors {
    allow_origins = ["example.com"]
  }
}

resource "aws_lambda_function_url" "no_cors" {
  function_name      = "example"
  authorization_type = "AWS_IAM"
}

resource "aws_lambda_function_url" "no_origins" {
  function_name      = "example"
  authorization_type = "AWS_IAM"
  cors {
    allow_headers = ["example-header"]
  }
}
