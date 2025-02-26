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
control_id=$(echo "aws.controls.$service.$control_number" | tr '[:lower:]' '[:upper:]')

cat <<EOF >>"../${service}_test.rego"

test_${service}_${control_number}_valid_input if {
	denied_rules := controls.deny with input as data.mocks.${service}["${control_number}"].pass
	every rule in denied_rules {
		rule.id.opa != "$control_id"
	}
}

test_${service}_${control_number}_invalid_input if {
	denied_rules := controls.deny with input as data.mocks.${service}["$control_number"].fail
	some rule in denied_rules
	rule.id.opa == "$control_id"
}
EOF
