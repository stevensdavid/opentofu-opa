package aws.control_tower

import rego.v1

import input as tfplan

# Root user UID can be integer 0 or a string
is_root_user(container) if container.user == 0

is_root_user(container) if regex.match(`0|root|^0:.*$|^root:.*$`, container.user)

# ECS defaults to root user if unspecified
is_root_user(container) if {
	not container.user
}

resources_after_change(type) := [result.change.after |
	some result in tfplan.resource_changes
	result.type == type
	some action in result.change.actions
	action in {"create", "update"}
]

deny contains {
	"control": "CT.ECS.PR.1",
	"reason": "Require Amazon ECS Fargate Services to run on the latest Fargate platform version",
} if {
	some resource in resources_after_change("aws_ecs_service")
	resource.launch_type == "FARGATE"
	resource.platform_version != "LATEST"
}

deny contains {
	"control": "CT.ECS.PR.2",
	"reason": "Public IP should not be assigned to ECS service",
} if {
	some resource in resources_after_change("aws_ecs_service")
	some network in resource.network_configuration
	network.assign_public_ip == true
}

deny contains {
	"control": "CT.ECS.PR.3",
	"reason": "Task definitions should not run as root",
} if {
	some resource in resources_after_change("aws_ecs_task_definition")
	some container in json.unmarshal(resource.container_definitions)
	is_root_user(container)
}

deny contains {
	"control": "CT.ECS.PR.8",
	"reason": "Task definitions should have secure networking modes and user definitions",
} if {
	some resource in resources_after_change("aws_ecs_task_definition")
	resource.network_mode == "host"
	some container in json.unmarshal(resource.container_definitions)
	not container.privileged
	is_root_user(container)
}
