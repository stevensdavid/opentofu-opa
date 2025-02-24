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

resource_after_change(type) := result if {
	some resource in tfplan.resource_changes
	resource.type == type
	some action in resource.change.actions
	action in {"create", "update"}
	result := resource.change.after
}

deny contains {
	"control": "CT.ECS.PR.1",
	"reason": "Require Amazon ECS Fargate Services to run on the latest Fargate platform version",
} if {
	resource := resource_after_change("aws_ecs_service")
	resource.launch_type == "FARGATE"
	resource.platform_version != "LATEST"
}

deny contains {
	"control": "ecs.2",
	"reason": "Public IP should not be assigned to ECS service",
} if {
	resource := resource_after_change("aws_ecs_service")
	resource.network_configuration[_].assign_public_ip == true
}

deny contains {
	"control": "CT.ECS.PR.8",
	"reason": "Task definitions should have secure networking modes and user definitions",
} if {
	resource := resource_after_change("aws_ecs_task_definition")
	resource.network_mode == "host"
	some container in json.unmarshal(resource.container_definitions)
	not container.privileged
	is_root_user(container)
}
