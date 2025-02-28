package utils

import rego.v1

resources(plan, type) := [
{"address": result.address, "configuration": result.change.after} |
	some result in plan.resource_changes
	result.type == type
	some action in result.change.actions
	action in {"create", "update"}
]
