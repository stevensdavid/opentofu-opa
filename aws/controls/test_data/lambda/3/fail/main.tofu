resource "aws_lambda_layer_version_permission" "invalid" {
  action         = "lambda:GetLayerVersion"
  layer_name     = "arn:aws:lambda:us-west-2:123456654321:layer:test_layer1"
  principal      = "*"
  statement_id   = "example"
  version_number = 1
}
