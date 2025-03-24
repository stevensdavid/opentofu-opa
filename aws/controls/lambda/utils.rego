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
