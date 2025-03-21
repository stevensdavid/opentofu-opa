package aws.controls.rds_test

import data.aws.controls
import data.aws.controls.rds

test_evaluate_rds_1_valid_input if count(rds.evaluate_rds_1(controls.mocks.rds["1"].pass)) == 0

test_evaluate_rds_1_invalid_input if count(rds.evaluate_rds_1(controls.mocks.rds["1"].fail)) == 2

test_evaluate_rds_2_valid_input if count(rds.evaluate_rds_2(controls.mocks.rds["2"].pass)) == 0

# test_evaluate_rds_2_invalid_input if count(rds.evaluate_rds_2(controls.mocks.rds["2"].fail)) == 4
test_evaluate_rds_2_invalid_input if {
	result := rds.evaluate_rds_2(controls.mocks.rds["2"].fail)
	count(result) == 4
}

test_evaluate_rds_3_valid_input if count(rds.evaluate_rds_3(controls.mocks.rds["3"].pass)) == 0

test_evaluate_rds_3_invalid_input if count(rds.evaluate_rds_3(controls.mocks.rds["3"].fail)) == 2

test_evaluate_rds_4_valid_input if count(rds.evaluate_rds_4(controls.mocks.rds["4"].pass)) == 0

test_evaluate_rds_4_invalid_input if count(rds.evaluate_rds_4(controls.mocks.rds["4"].fail)) == 2

test_evaluate_rds_5_valid_input if count(rds.evaluate_rds_5(controls.mocks.rds["5"].pass)) == 0

test_evaluate_rds_5_invalid_input if count(rds.evaluate_rds_5(controls.mocks.rds["5"].fail)) == 1

test_evaluate_rds_6_valid_input if count(rds.evaluate_rds_6(controls.mocks.rds["6"].pass)) == 0

test_evaluate_rds_6_invalid_input if count(rds.evaluate_rds_6(controls.mocks.rds["6"].fail)) == 8

test_evaluate_rds_7_valid_input if count(rds.evaluate_rds_7(controls.mocks.rds["7"].pass)) == 0

test_evaluate_rds_7_invalid_input if count(rds.evaluate_rds_7(controls.mocks.rds["7"].fail)) == 2

test_evaluate_rds_8_valid_input if count(rds.evaluate_rds_8(controls.mocks.rds["8"].pass)) == 0

test_evaluate_rds_8_invalid_input if count(rds.evaluate_rds_8(controls.mocks.rds["8"].fail)) == 3

test_evaluate_rds_9_valid_input if count(rds.evaluate_rds_9(controls.mocks.rds["9"].pass)) == 0

test_evaluate_rds_9_invalid_input if count(rds.evaluate_rds_9(controls.mocks.rds["9"].fail)) == 2

test_evaluate_rds_10_valid_input if count(rds.evaluate_rds_10(controls.mocks.rds["10"].pass)) == 0

test_evaluate_rds_10_invalid_input if count(rds.evaluate_rds_10(controls.mocks.rds["10"].fail)) == 2

test_evaluate_rds_11_valid_input if count(rds.evaluate_rds_11(controls.mocks.rds["11"].pass)) == 0

test_evaluate_rds_11_invalid_input if count(rds.evaluate_rds_11(controls.mocks.rds["11"].fail)) == 2

test_evaluate_rds_12_valid_input if count(rds.evaluate_rds_12(controls.mocks.rds["12"].pass)) == 0

test_evaluate_rds_12_invalid_input if count(rds.evaluate_rds_12(controls.mocks.rds["12"].fail)) == 4

test_evaluate_rds_13_valid_input if count(rds.evaluate_rds_13(controls.mocks.rds["13"].pass)) == 0

test_evaluate_rds_13_invalid_input if count(rds.evaluate_rds_13(controls.mocks.rds["13"].fail)) == 2

test_evaluate_rds_14_valid_input if count(rds.evaluate_rds_14(controls.mocks.rds["14"].pass)) == 0

test_evaluate_rds_14_invalid_input if count(rds.evaluate_rds_14(controls.mocks.rds["14"].fail)) == 4

test_evaluate_rds_15_valid_input if count(rds.evaluate_rds_15(controls.mocks.rds["15"].pass)) == 0

test_evaluate_rds_15_invalid_input if count(rds.evaluate_rds_15(controls.mocks.rds["15"].fail)) == 2

test_evaluate_rds_16_valid_input if count(rds.evaluate_rds_16(controls.mocks.rds["16"].pass)) == 0

test_evaluate_rds_16_invalid_input if count(rds.evaluate_rds_16(controls.mocks.rds["16"].fail)) == 4

test_evaluate_rds_17_valid_input if count(rds.evaluate_rds_17(controls.mocks.rds["17"].pass)) == 0

test_evaluate_rds_17_invalid_input if count(rds.evaluate_rds_17(controls.mocks.rds["17"].fail)) == 2
