package aws.controls.iam_test

import rego.v1

import data.aws.controls
import data.aws.controls.iam

test_evaluate_iam_1_valid_input if count(iam.evaluate_iam_1(controls.mocks.iam["1"].pass)) == 0

test_evaluate_iam_1_invalid_input if count(iam.evaluate_iam_1(controls.mocks.iam["1"].fail)) == 11

test_evaluate_iam_2_valid_input if count(iam.evaluate_iam_2(controls.mocks.iam["2"].pass)) == 0

test_evaluate_iam_2_invalid_input if count(iam.evaluate_iam_2(controls.mocks.iam["2"].fail)) == 11
