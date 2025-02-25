package aws.controls

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
	"id": {"control_tower": "CT.ECS.PR.1", "fsbp": "ECS.10"},
	"severity": "medium",
	"reason": "Require Amazon ECS Fargate Services to run on the latest Fargate platform version",
} if {
	some resource in resources_after_change("aws_ecs_service")
	resource.launch_type == "FARGATE"
	resource.platform_version != "LATEST"
}

# This rule has three cases that lead to failure:
# 1. The setting is present and not enabled
deny contains {
	"id": {"control_tower": "CT.ECS.PR.2", "fsbp": "ECS.12"},
	"severity": "medium",
	"reason": "ECS clusters should enable container insights",
} if {
	some resource in resources_after_change("aws_ecs_cluster")
	some setting in resource.setting
	setting.name == "containerInsights"
	setting.value != "enabled"
}

# 2. The setting is not present
deny contains {
	"id": {"control_tower": "CT.ECS.PR.2"},
	"reason": "ECS clusters should enable container insights",
} if {
	some resource in resources_after_change("aws_ecs_cluster")
	every setting in resource.setting {
		setting.name != "containerInsights"
	}
}

# 3. No settings are set
deny contains {
	"id": {"control_tower": "CT.ECS.PR.2"},
	"reason": "ECS clusters should enable container insights",
} if {
	some resource in resources_after_change("aws_ecs_cluster")
	not resource.setting
}

deny contains {
	"id": {"control_tower": "CT.ECS.PR.3"},
	"reason": "Task definitions should not run as root",
} if {
	some resource in resources_after_change("aws_ecs_task_definition")
	some container in json.unmarshal(resource.container_definitions)
	is_root_user(container)
}

deny contains {"id": {"control_tower": "CT.ECS.PR.4"}, "reason": "Tasks should use 'awsvpc' networking mode"} if {
	some resource in resources_after_change("aws_ecs_task_definition")
	resource.network_mode != "awsvpc"
}

# Task networking mode doesn't default to awsvpc, so the case where it isn't set
# is also denied.
deny contains {"id": {"control_tower": "CT.ECS.PR.4"}, "reason": "Tasks should use 'awsvpc' networking mode"} if {
	some resource in resources_after_change("aws_ecs_task_definition")
	not resource.network_mode
}

deny contains {
	"id": {"control_tower": "CT.ECS.PR.5", "fsbp": "ECS.9"},
	"severity": "high",
	"reason": "Task containers must have a logging configuration",
} if {
	some resource in resources_after_change("aws_ecs_task_definition")
	some container in json.unmarshal(resource.container_definitions)
	not container.logConfiguration
}

deny contains {
	"id": {"control_tower": "CT.ECS.PR.6", "fsbp": "ECS.5"},
	"severity": "high",
	"reason": "Task containers should have read-only root filesystems",
} if {
	some resource in resources_after_change("aws_ecs_task_definition")
	some container in json.unmarshal(resource.container_definitions)
	not container.readonlyRootFilesystem
}

deny contains {
	"id": {"control_tower": "CT.ECS.PR.7"},
	"reason": "Task containers should specify memory usage limits",
} if {
	some resource in resources_after_change("aws_ecs_task_definition")
	some container in json.unmarshal(resource.container_definitions)
	not container.memory
}

deny contains {
	"id": {"control_tower": "CT.ECS.PR.8", "fsbp": "ECS.1"},
	"severity": "high",
	"reason": "Task definitions should have secure networking modes and user definitions",
} if {
	some resource in resources_after_change("aws_ecs_task_definition")
	resource.network_mode == "host"
	some container in json.unmarshal(resource.container_definitions)
	not container.privileged
	is_root_user(container)
}

deny contains {
	"id": {"control_tower": "CT.ECS.PR.9", "fsbp": "ECS.2"},
	"severity": "high",
	"reason": "Public IP should not be assigned to ECS service",
} if {
	some resource in resources_after_change("aws_ecs_service")
	some network in resource.network_configuration
	network.assign_public_ip == true
}

deny contains {
	"id": {"control_tower": "CT.ECS.PR.10", "fsbp": "ECS.3"},
	"severity": "high",
	"reason": "ECS tasks should not use the host's process namespace",
} if {
	some resource in resources_after_change("aws_ecs_task_definition")
	resource.pid_mode == "host"
}

deny contains {
	"id": {"control_tower": "CT.ECS.PR.11", "fsbp": "ECS.4"},
	"severity": "high",
	"reason": "ECS tasks should run as non-privileged",
} if {
	some resource in resources_after_change("aws_ecs_task_definition")
	some container in json.unmarshal(resource.container_definitions)
	container.privileged
}

deny contains {
	"id": {"control_tower": "CT.ECS.PR.12", "fsbp": "ECS.8"},
	"severity": "high",
	"reason": "ECS tasks do not pass secrets as container environment variables",
} if {
	some resource in resources_after_change("aws_ecs_task_definition")
	some container in json.unmarshal(resource.container_definitions)
	some variable in container.environment
	variable.name in {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "ECS_ENGINE_AUTH_DATA"}
}
