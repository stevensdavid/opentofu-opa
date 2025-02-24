package aws.control_tower_test

import rego.v1

import data.aws.control_tower

test_ecs_pr_1 if {
	count(control_tower.deny) > 0 with input as data.mocks.ecs.pr["1"].fail
	count(control_tower.deny) == 0 with input as data.mocks.ecs.pr["1"].pass
}

test_ecs_pr_2 if {
	count(control_tower.deny) > 0 with input as data.mocks.ecs.pr["2"].fail
	count(control_tower.deny) == 0 with input as data.mocks.ecs.pr["2"].pass
}

test_ecs_pr_8 if {
	count(control_tower.deny) > 0 with input as data.mocks.ecs.pr["8"].fail
	count(control_tower.deny) == 0 with input as data.mocks.ecs.pr["8"].pass
}
