package aws.controls.rds

import data.utils

evaluate_rds_1(plan) := {violation |
	some resource in utils.resources(plan, "aws_db_instance")
	not resource.configuration.multi_az
	standard_engine(resource.configuration.engine)

	violation := {
		"id": {"opa": "aws.controls.rds.1", "control_tower": "CT.RDS.PR.1"},
		"reason": "Require that an Amazon RDS database instance is configured with multiple Availability Zones",
		"resource": resource.address,
	}
}

evaluate_rds_2(plan) := {violation |
	some resource in utils.resources(plan, "aws_db_instance")
	standard_engine(resource.configuration.engine)

	# The case of invalid monitoring intervals is handled by the Terraform provider,
	# and the provider defaults the field to 0. We only have to check the = 0 case.
	resource.configuration.monitoring_interval == 0

	violation := {
		"id": {"opa": "aws.controls.rds.2", "control_tower": "CT.RDS.PR.2"},
		"reason": "Require an Amazon RDS database instance or cluster to have enhanced monitoring configured",
		"resource": resource.address,
	}
}

evaluate_rds_3(plan) := {violation |
	some resource in utils.resources(plan, "aws_rds_cluster")
	utils.null_or_false(resource.configuration.deletion_protection)

	violation := {
		"id": {"opa": "aws.controls.rds.3", "control_tower": "CT.RDS.PR.3"},
		"reason": "Require an Amazon RDS cluster to have deletion protection configured",
		"resource": resource.address,
	}
}

evaluate_rds_4(plan) := {violation |
	some resource in utils.resources(plan, "aws_rds_cluster")
	resource.configuration.engine in {"aurora-mysql", "aurora-postgresql"}
	utils.null_or_false(resource.configuration.iam_database_authentication_enabled)

	violation := {
		"id": {"opa": "aws.controls.rds.4", "control_tower": "CT.RDS.PR.4"},
		"reason": "Require an Amazon RDS database cluster to have AWS IAM database authentication configured",
		"resource": resource.address,
	}
}
