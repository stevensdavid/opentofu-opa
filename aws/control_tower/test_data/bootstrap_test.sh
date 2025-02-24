#!/bin/bash
set -euo pipefail

path=$1
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
