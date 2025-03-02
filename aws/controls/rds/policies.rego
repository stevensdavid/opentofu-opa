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
