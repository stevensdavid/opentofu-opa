resource "aws_lambda_function_url" "no_cors" {
  function_name      = "example"
  authorization_type = "AWS_IAM"
}

resource "aws_lambda_function_url" "no_origin_restriction" {
  function_name      = "example"
  authorization_type = "AWS_IAM"
  cors {
    allow_methods = ["GET"]
  }
}

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
