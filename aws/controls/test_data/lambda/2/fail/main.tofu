resource "aws_lambda_function" "missing_sg_ids" {
  function_name = "lambda"
  role          = "arn:aws:iam::123456789012:role/example"
  filename      = "bundle.zip"
  handler       = "index.Handler"
  runtime       = "nodejs22.x"
  vpc_config {
    subnet_ids         = ["subnet-01234567890abcdef"]
    security_group_ids = []
  }
}

resource "aws_lambda_function" "missing_subnet_ids" {
  function_name = "lambda"
  role          = "arn:aws:iam::123456789012:role/example"
  filename      = "bundle.zip"
  handler       = "index.Handler"
  runtime       = "nodejs22.x"
  vpc_config {
    subnet_ids         = []
    security_group_ids = ["sg-0123456789abcdef"]
  }
}

resource "aws_lambda_function" "missing_both" {
  function_name = "lambda"
  role          = "arn:aws:iam::123456789012:role/example"
  filename      = "bundle.zip"
  handler       = "index.Handler"
  runtime       = "nodejs22.x"
  vpc_config {
    subnet_ids         = []
    security_group_ids = []
  }
}

resource "aws_lambda_function" "missing_vpc_config" {
  function_name = "lambda"
  filename      = "bundle.zip"
  handler       = "index.Handler"
  runtime       = "nodejs22.x"
  role          = "arn:aws:iam::123456789012:role/example"
}
