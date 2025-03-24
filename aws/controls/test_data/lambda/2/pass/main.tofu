resource "aws_lambda_function" "valid" {
  function_name = "lambda"
  role          = "arn:aws:iam::123456789012:role/example"
  filename      = "bundle.zip"
  handler       = "index.Handler"
  runtime       = "nodejs22.x"
  vpc_config {
    subnet_ids         = ["subnet-01234567890abcdef"]
    security_group_ids = ["sg-01234567890abcdef"]
  }
}
