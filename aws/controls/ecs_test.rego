package aws.controls_test

import rego.v1

import data.aws.controls

test_ecs_1_valid_input if {
	denied_rules := controls.evaluate_ecs(data.mocks.ecs["1"].pass)

	every rule in denied_rules {
		rule.id.opa != "aws.controls.ecs.1"
	}
}

test_ecs_1_invalid_input if {
	denied_rules := controls.evaluate_ecs(data.mocks.ecs["1"].fail)
	some rule in denied_rules
	rule.id.opa == "aws.controls.ecs.1"
}

test_ecs_2_valid_input if {
	denied_rules := controls.evaluate_ecs(data.mocks.ecs["2"].pass)
	every rule in denied_rules {
		rule.id.opa != "aws.controls.ecs.2"
	}
}

test_ecs_2_invalid_input if {
	denied_rules := controls.evaluate_ecs(data.mocks.ecs["2"].fail)
	some rule in denied_rules
	rule.id.opa == "aws.controls.ecs.2"
}

test_ecs_3_valid_input if {
	denied_rules := controls.evaluate_ecs(data.mocks.ecs["3"].pass)
	every rule in denied_rules {
		rule.id.opa != "aws.controls.ecs.3"
	}
}

test_ecs_3_invalid_input if {
	denied_rules := controls.evaluate_ecs(data.mocks.ecs["3"].fail)
	some rule in denied_rules
	rule.id.opa == "aws.controls.ecs.3"
}

test_ecs_4_valid_input if {
	denied_rules := controls.evaluate_ecs(data.mocks.ecs["4"].pass)
	every rule in denied_rules {
		rule.id.opa != "aws.controls.ecs.4"
	}
}

test_ecs_4_invalid_input if {
	denied_rules := controls.evaluate_ecs(data.mocks.ecs["4"].fail)
	some rule in denied_rules
	rule.id.opa == "aws.controls.ecs.4"
}

test_ecs_5_valid_input if {
	denied_rules := controls.evaluate_ecs(data.mocks.ecs["5"].pass)
	every rule in denied_rules {
		rule.id.opa != "aws.controls.ecs.5"
	}
}

test_ecs_5_invalid_input if {
	denied_rules := controls.evaluate_ecs(data.mocks.ecs["5"].fail)
	some rule in denied_rules
	rule.id.opa == "aws.controls.ecs.5"
}

test_ecs_6_valid_input if {
	denied_rules := controls.evaluate_ecs(data.mocks.ecs["6"].pass)
	every rule in denied_rules {
		rule.id.opa != "aws.controls.ecs.6"
	}
}

test_ecs_6_invalid_input if {
	denied_rules := controls.evaluate_ecs(data.mocks.ecs["6"].fail)
	some rule in denied_rules
	rule.id.opa == "aws.controls.ecs.6"
}

test_ecs_7_valid_input if {
	denied_rules := controls.evaluate_ecs(data.mocks.ecs["7"].pass)
	every rule in denied_rules {
		rule.id.opa != "aws.controls.ecs.7"
	}
}

test_ecs_7_invalid_input if {
	denied_rules := controls.evaluate_ecs(data.mocks.ecs["7"].fail)
	some rule in denied_rules
	rule.id.opa == "aws.controls.ecs.7"
}

test_ecs_8_valid_input if {
	denied_rules := controls.evaluate_ecs(data.mocks.ecs["8"].pass)
	every rule in denied_rules {
		rule.id.opa != "aws.controls.ecs.8"
	}
}

test_ecs_8_invalid_input if {
	denied_rules := controls.evaluate_ecs(data.mocks.ecs["8"].fail)
	some rule in denied_rules
	rule.id.opa == "aws.controls.ecs.8"
}

test_ecs_9_valid_input if {
	denied_rules := controls.evaluate_ecs(data.mocks.ecs["9"].pass)
	every rule in denied_rules {
		rule.id.opa != "aws.controls.ecs.9"
	}
}

test_ecs_9_invalid_input if {
	denied_rules := controls.evaluate_ecs(data.mocks.ecs["9"].fail)
	some rule in denied_rules
	rule.id.opa == "aws.controls.ecs.9"
}

test_ecs_10_valid_input if {
	denied_rules := controls.evaluate_ecs(data.mocks.ecs["10"].pass)
	every rule in denied_rules {
		rule.id.opa != "aws.controls.ecs.10"
	}
}

test_ecs_10_invalid_input if {
	denied_rules := controls.evaluate_ecs(data.mocks.ecs["10"].fail)
	some rule in denied_rules
	rule.id.opa == "aws.controls.ecs.10"
}

test_ecs_11_valid_input if {
	denied_rules := controls.evaluate_ecs(data.mocks.ecs["11"].pass)
	every rule in denied_rules {
		rule.id.opa != "aws.controls.ecs.11"
	}
}

test_ecs_11_invalid_input if {
	denied_rules := controls.evaluate_ecs(data.mocks.ecs["11"].fail)
	some rule in denied_rules
	rule.id.opa == "aws.controls.ecs.11"
}

test_ecs_12_valid_input if {
	denied_rules := controls.evaluate_ecs(data.mocks.ecs["12"].pass)
	every rule in denied_rules {
		rule.id.opa != "aws.controls.ecs.12"
	}
}

test_ecs_12_invalid_input if {
	denied_rules := controls.evaluate_ecs(data.mocks.ecs["12"].fail)
	some rule in denied_rules
	rule.id.opa == "aws.controls.ecs.12"
}

test_ecs_13_valid_input if {
	denied_rules := controls.evaluate_ecs(data.mocks.ecs["13"].pass)
	every rule in denied_rules {
		rule.id.opa != "aws.controls.ecs.13"
	}
}

test_ecs_13_invalid_input if {
	denied_rules := controls.evaluate_ecs(data.mocks.ecs["13"].fail)
	some rule in denied_rules
	rule.id.opa == "aws.controls.ecs.13"
}
