package aws.controls.rds

import data.utils

evaluate_rds_1(plan) := {violation |
	some resource in utils.resources(plan, "aws_db_instance")
	not resource.configuration.multi_az

	violation := {
		"id": {"opa": "aws.controls.rds.1", "control_tower": "CT.RDS.PR.1"},
		"reason": "Require that an Amazon RDS database instance is configured with multiple Availability Zones",
		"resource": resource.address,
	}
}
