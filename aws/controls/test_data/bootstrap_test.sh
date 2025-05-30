#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

path=$1
IFS='/' read -r -a path_parts <<<"$path"
service="${path_parts[0]}"
control_number="${path_parts[1]}"

mkdir -p "$path" "$path/pass" "$path/fail"

cat <<EOF >"$path/main.tofu"
provider "aws" {
  region = "eu-north-1"
}

module "pass" {
  source              = "./pass"
}

module "fail" {
  source              = "./fail"
}
EOF

touch "$path/pass/main.tofu" "$path/fail/main.tofu"
control_id="aws.controls.$service.$control_number"

function_name="evaluate_${service}_${control_number}"

mkdir -p "../${service}"
# Create missing files
if [ ! -f "../${service}/main.rego" ]; then
    cat <<EOF >>"../${service}/main.rego"
package aws.controls.$service

import rego.v1

evaluate(plan) := union({})
EOF
fi
if [ ! -f "../${service}/main_test.rego" ]; then
    cat <<EOF >>"../${service}/main_test.rego"
package aws.controls.${service}_test

import rego.v1

import data.aws.controls
import data.aws.controls.${service}

test_evaluate_includes_all_rules if {
	every rule_id in object.keys(controls.mocks.${service}) {
		opa_rule_id := sprintf("aws.controls.${service}.%s", [rule_id])
		denies := ${service}.evaluate(controls.mocks.${service}[rule_id].fail)
		some deny in denies
		deny.id.opa == opa_rule_id

		permits := ${service}.evaluate(controls.mocks.${service}[rule_id].pass)
		every unrelated_deny in permits {
			unrelated_deny.id.opa != opa_rule_id
		}
	}
}
EOF
fi

if [ ! -f "../${service}/policies.rego" ]; then
    echo "Writing to ../${service}/policies.rego"
    cat <<EOF >>"../${service}/policies.rego"
package aws.controls.${service}

import data.aws.utils as aws_utils
import data.utils

import rego.v1
EOF
fi

if [ ! -f "../${service}/policies_test.rego" ]; then
    echo "Writing to ../${service}/policies_test.rego"
    cat <<EOF >>"../${service}/policies_test.rego"
package aws.controls.${service}_test

import rego.v1

import data.aws.controls
import data.aws.controls.${service}
EOF
fi

cat <<EOF >>"../${service}/policies_test.rego"

test_${function_name}_valid_input if count(${service}.$function_name(controls.mocks.${service}["$control_number"].pass)) == 0

test_${function_name}_invalid_input if count(${service}.$function_name(controls.mocks.${service}["$control_number"].fail)) == 1
EOF

docs_link="https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrols${service}${control_number}"

cat <<EOF >>"../${service}/policies.rego"

$function_name(plan) := {violation |
	some {"configuration": configuration, "address": address} in utils.resources(plan, "aws_")

	violation := {
		"id": {"opa": "$control_id"},
		"reason": "",
		"resource": address,
		"docs": "$docs_link",
	}
}
EOF

# sed has different syntax on macOS
os=$(uname)
if [ "$os" == "Darwin" ]; then
    sed -i '' 's/}/, '"$function_name"'(plan)}/' "../${service}/main.rego"
else
    sed -i "s/}/, $function_name(plan)}/" "../${service}/main.rego"
fi
