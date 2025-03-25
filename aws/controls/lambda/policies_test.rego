package aws.controls.lambda_test

import rego.v1

import data.aws.controls
import data.aws.controls.lambda

test_evaluate_lambda_1_valid_input if count(lambda.evaluate_lambda_1(controls.mocks.lambda["1"].pass)) == 0

test_evaluate_lambda_1_invalid_input if count(lambda.evaluate_lambda_1(controls.mocks.lambda["1"].fail)) == 3

test_evaluate_lambda_2_valid_input if count(lambda.evaluate_lambda_2(controls.mocks.lambda["2"].pass)) == 0

test_evaluate_lambda_2_invalid_input if count(lambda.evaluate_lambda_2(controls.mocks.lambda["2"].fail)) == 4

test_evaluate_lambda_3_valid_input if count(lambda.evaluate_lambda_3(controls.mocks.lambda["3"].pass)) == 0

test_evaluate_lambda_3_invalid_input if count(lambda.evaluate_lambda_3(controls.mocks.lambda["3"].fail)) == 1
