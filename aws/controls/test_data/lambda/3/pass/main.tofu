resource "aws_lambda_layer_version_permission" "principal" {
  action         = "lambda:GetLayerVersion"
  layer_name     = "arn:aws:lambda:us-west-2:123456654321:layer:test_layer1"
  principal      = "123456789012"
  statement_id   = "example"
  version_number = 1
}

resource "aws_lambda_layer_version_permission" "org_id" {
  action          = "lambda:GetLayerVersion"
  layer_name      = "arn:aws:lambda:us-west-2:123456654321:layer:test_layer1"
  principal       = "*"
  organization_id = "o-a1b2c3d4e5f"
  statement_id    = "example"
  version_number  = 1
}
