package aws.control_tower_test

import rego.v1

import data.aws.control_tower

test_ecs_pr_1_valid_input if {
	denied_rules := control_tower.deny with input as data.mocks.ecs.pr["1"].pass
	every rule in denied_rules {
		rule.control != "CT.ECS.PR.1"
	}
}

test_ecs_pr_1_invalid_input if {
	denied_rules := control_tower.deny with input as data.mocks.ecs.pr["1"].fail
	some rule in denied_rules
	rule.control == "CT.ECS.PR.1"
}

test_ecs_pr_2_valid_input if {
	denied_rules := control_tower.deny with input as data.mocks.ecs.pr["2"].pass
	every rule in denied_rules {
		rule.control != "CT.ECS.PR.2"
	}
}

test_ecs_pr_2_invalid_input if {
	denied_rules := control_tower.deny with input as data.mocks.ecs.pr["2"].fail
	some rule in denied_rules
	rule.control == "CT.ECS.PR.2"
}

test_ecs_pr_3_valid_input if {
	denied_rules := control_tower.deny with input as data.mocks.ecs.pr["3"].pass
	every rule in denied_rules {
		rule.control != "CT.ECS.PR.3"
	}
}

test_ecs_pr_3_invalid_input if {
	denied_rules := control_tower.deny with input as data.mocks.ecs.pr["3"].fail
	some rule in denied_rules
	rule.control == "CT.ECS.PR.3"
}

test_ecs_pr_4_valid_input if {
	denied_rules := control_tower.deny with input as data.mocks.ecs.pr["4"].pass
	every rule in denied_rules {
		rule.control != "CT.ECS.PR.4"
	}
}

test_ecs_pr_4_invalid_input if {
	denied_rules := control_tower.deny with input as data.mocks.ecs.pr["4"].fail
	some rule in denied_rules
	rule.control == "CT.ECS.PR.4"
}

test_ecs_pr_8_valid_input if {
	denied_rules := control_tower.deny with input as data.mocks.ecs.pr["8"].pass
	every rule in denied_rules {
		rule.control != "CT.ECS.PR.8"
	}
}

test_ecs_pr_8_invalid_input if {
	denied_rules := control_tower.deny with input as data.mocks.ecs.pr["8"].fail
	some rule in denied_rules
	rule.control == "CT.ECS.PR.8"
}
