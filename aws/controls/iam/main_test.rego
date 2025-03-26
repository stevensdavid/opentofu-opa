package aws.controls.iam_test

import rego.v1

import data.aws.controls
import data.aws.controls.iam

test_evaluate_includes_all_rules if {
	every rule_id in object.keys(controls.mocks.iam) {
		opa_rule_id := sprintf("aws.controls.iam.%s", [rule_id])
		denies := iam.evaluate(controls.mocks.iam[rule_id].fail)
		some deny in denies
		deny.id.opa == opa_rule_id

		permits := iam.evaluate(controls.mocks.iam[rule_id].pass)
		every unrelated_deny in permits {
			unrelated_deny.id.opa != opa_rule_id
		}
	}
}
