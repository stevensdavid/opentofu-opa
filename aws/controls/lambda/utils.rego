package aws.controls.lambda

import data.aws.utils as aws_utils
import data.utils
import rego.v1

public_access(permission) if {
	not aws_utils.matches_account_id(permission.principal)
	not aws_utils.matches_iam_principal(permission.principal)
	utils.falsy(permission.source_arn)
	not aws_utils.matches_account_id(permission.source_account)
	utils.falsy(permission.principal_org_id)
	permission.function_url_auth_type != "AWS_IAM"
}

public_access(permission) if permission.function_url_auth_type == "NONE"

valid_vpc_config(lambda) if {
	count(lambda.vpc_config) == 1
	count(lambda.vpc_config[0].security_group_ids) > 0
	count(lambda.vpc_config[0].subnet_ids) > 0
}

wildcard_cors_origin(function_url) if count(function_url.cors) == 0

wildcard_cors_origin(function_url) if utils.falsy(function_url.cors[0].allow_origins)

wildcard_cors_origin(function_url) if {
	some origin in function_url.cors[0].allow_origins
	origin in {"*", "https://*", "http://*"}
}
