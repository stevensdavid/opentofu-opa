package aws.controls_test

import rego.v1

import data.aws.controls

test_evaluate_all_includes_all_rules if {
	every service in object.keys(controls.mocks) {
		every rule_id in object.keys(controls.mocks[service]) {
			opa_rule_id := sprintf("aws.controls.%s.%s", [service, rule_id])
			denies := controls.evaluate_all(controls.mocks[service][rule_id].fail)
			some deny in denies
			deny.id.opa == opa_rule_id

			permits := controls.evaluate_all(controls.mocks[service][rule_id].pass)
			every unrelated_deny in permits {
				unrelated_deny.id.opa != opa_rule_id
			}
		}
	}
}

test_all_rules_have_severity if {
	every service in object.keys(controls.mocks) {
		every rule_id in object.keys(controls.mocks[service]) {
			denies := controls.evaluate_all(controls.mocks[service][rule_id].fail)
			every deny in denies {
				deny.severity
			}
		}
	}
}

test_all_rules_have_reason if {
	every service in object.keys(controls.mocks) {
		every rule_id in object.keys(controls.mocks[service]) {
			denies := controls.evaluate_all(controls.mocks[service][rule_id].fail)
			every deny in denies {
				deny.reason
			}
		}
	}
}

test_all_rules_have_id if {
	every service in object.keys(controls.mocks) {
		every rule_id in object.keys(controls.mocks[service]) {
			denies := controls.evaluate_all(controls.mocks[service][rule_id].fail)
			every deny in denies {
				deny.id.opa
			}
		}
	}
}

test_all_rules_have_docs_link if {
	every service in object.keys(controls.mocks) {
		every rule_id in object.keys(controls.mocks[service]) {
			denies := controls.evaluate_all(controls.mocks[service][rule_id].fail)
			every deny in denies {
				deny.docs
			}
		}
	}
}

test_all_rules_have_resource if {
	every service in object.keys(controls.mocks) {
		every rule_id in object.keys(controls.mocks[service]) {
			denies := controls.evaluate_all(controls.mocks[service][rule_id].fail)
			every deny in denies {
				deny.resource
			}
		}
	}
}
