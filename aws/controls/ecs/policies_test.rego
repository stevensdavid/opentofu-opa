package aws.controls.ecs_test

import rego.v1

import data.aws.controls
import data.aws.controls.ecs

test_ecs_1_valid_input if count(ecs.evaluate_ecs_1(controls.mocks.ecs["1"].pass)) == 0

test_ecs_1_invalid_input if ecs.evaluate_ecs_1(controls.mocks.ecs["1"].fail)

test_ecs_2_valid_input if count(ecs.evaluate_ecs_2(controls.mocks.ecs["2"].pass)) == 0

test_ecs_2_invalid_input if ecs.evaluate_ecs_2(controls.mocks.ecs["2"].fail)

test_ecs_3_valid_input if count(ecs.evaluate_ecs_3(controls.mocks.ecs["3"].pass)) == 0

test_ecs_3_invalid_input if ecs.evaluate_ecs_3(controls.mocks.ecs["3"].fail)

test_ecs_4_valid_input if count(ecs.evaluate_ecs_4(controls.mocks.ecs["4"].pass)) == 0

test_ecs_4_invalid_input if ecs.evaluate_ecs_4(controls.mocks.ecs["4"].fail)

test_ecs_5_valid_input if count(ecs.evaluate_ecs_5(controls.mocks.ecs["5"].pass)) == 0

test_ecs_5_invalid_input if ecs.evaluate_ecs_5(controls.mocks.ecs["5"].fail)

test_ecs_6_valid_input if count(ecs.evaluate_ecs_6(controls.mocks.ecs["6"].pass)) == 0

test_ecs_6_invalid_input if ecs.evaluate_ecs_6(controls.mocks.ecs["6"].fail)

test_ecs_7_valid_input if count(ecs.evaluate_ecs_7(controls.mocks.ecs["7"].pass)) == 0

test_ecs_7_invalid_input if ecs.evaluate_ecs_7(controls.mocks.ecs["7"].fail)

test_ecs_8_valid_input if count(ecs.evaluate_ecs_8(controls.mocks.ecs["8"].pass)) == 0

test_ecs_8_invalid_input if ecs.evaluate_ecs_8(controls.mocks.ecs["8"].fail)

test_ecs_9_valid_input if count(ecs.evaluate_ecs_9(controls.mocks.ecs["9"].pass)) == 0

test_ecs_9_invalid_input if ecs.evaluate_ecs_9(controls.mocks.ecs["9"].fail)

test_ecs_10_valid_input if count(ecs.evaluate_ecs_10(controls.mocks.ecs["10"].pass)) == 0

test_ecs_10_invalid_input if ecs.evaluate_ecs_10(controls.mocks.ecs["10"].fail)

test_ecs_11_valid_input if count(ecs.evaluate_ecs_11(controls.mocks.ecs["11"].pass)) == 0

test_ecs_11_invalid_input if ecs.evaluate_ecs_11(controls.mocks.ecs["11"].fail)

test_ecs_12_valid_input if count(ecs.evaluate_ecs_12(controls.mocks.ecs["12"].pass)) == 0

test_ecs_12_invalid_input if ecs.evaluate_ecs_12(controls.mocks.ecs["12"].fail)

test_ecs_13_valid_input if count(ecs.evaluate_ecs_13(controls.mocks.ecs["13"].pass)) == 0

test_ecs_13_invalid_input if ecs.evaluate_ecs_13(controls.mocks.ecs["13"].fail)
