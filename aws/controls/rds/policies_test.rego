package aws.controls.rds_test

import data.aws.controls
import data.aws.controls.rds

test_evaluate_rds_1_valid_input if count(rds.evaluate_rds_1(controls.mocks.rds["1"].pass)) == 0

test_evaluate_rds_1_invalid_input if count(rds.evaluate_rds_1(controls.mocks.rds["1"].fail)) == 2

test_evaluate_rds_2_valid_input if count(rds.evaluate_rds_2(controls.mocks.rds["2"].pass)) == 0

# test_evaluate_rds_2_invalid_input if count(rds.evaluate_rds_2(controls.mocks.rds["2"].fail)) == 4
test_evaluate_rds_2_invalid_input if {
	result := rds.evaluate_rds_2(controls.mocks.rds["2"].fail)
	print(result)
	count(result) == 4
}

test_evaluate_rds_3_valid_input if count(rds.evaluate_rds_3(controls.mocks.rds["3"].pass)) == 0

test_evaluate_rds_3_invalid_input if count(rds.evaluate_rds_3(controls.mocks.rds["3"].fail)) == 2

test_evaluate_rds_4_valid_input if count(rds.evaluate_rds_4(controls.mocks.rds["4"].pass)) == 0

test_evaluate_rds_4_invalid_input if count(rds.evaluate_rds_4(controls.mocks.rds["4"].fail)) == 2
