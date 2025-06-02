resource "aws_lambda_function_url" "wildcard" {
  function_name      = "example"
  authorization_type = "AWS_IAM"
  cors {
    allow_origins = ["example.com", "*"]
  }
}

resource "aws_lambda_function_url" "http_wildcard" {
  function_name      = "example"
  authorization_type = "AWS_IAM"
  cors {
    allow_origins = ["example.com", "http://*"]
  }
}

resource "aws_lambda_function_url" "https_wildcard" {
  function_name      = "example"
  authorization_type = "AWS_IAM"
  cors {
    allow_origins = ["example.com", "https://*"]
  }
}
