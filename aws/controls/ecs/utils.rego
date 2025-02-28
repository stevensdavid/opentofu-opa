package aws.controls.ecs

import rego.v1

# Root user UID can be integer 0 or a string
is_root_user(container) if container.user == 0

is_root_user(container) if regex.match(`0|root|^0:.*$|^root:.*$`, container.user)

# ECS defaults to root user if unspecified
is_root_user(container) if {
	not container.user
}
