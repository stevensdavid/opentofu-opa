package aws.controls.rds_test

import data.aws.controls
import data.aws.controls.rds

test_evaluate_rds_1_valid_input if count(rds.evaluate_rds_1(controls.mocks.rds["1"].pass)) == 0

test_evaluate_rds_1_invalid_input if rds.evaluate_rds_1(controls.mocks.rds["1"].fail)

test_evaluate_rds_2_valid_input if count(rds.evaluate_rds_2(controls.mocks.rds["2"].pass)) == 0

test_evaluate_rds_2_invalid_input if {
	result := rds.evaluate_rds_2(controls.mocks.rds["2"].fail)
	print(result)
	count(result) == 2
}
