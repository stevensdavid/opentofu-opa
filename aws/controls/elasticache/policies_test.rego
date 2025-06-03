package aws.controls.elasticache_test

import rego.v1

import data.aws.controls
import data.aws.controls.elasticache

test_evaluate_elasticache_1_valid_input if count(elasticache.evaluate_elasticache_1(controls.mocks.elasticache["1"].pass)) == 0

test_evaluate_elasticache_1_invalid_input if count(elasticache.evaluate_elasticache_1(controls.mocks.elasticache["1"].fail)) == 4

test_evaluate_elasticache_2_valid_input if count(elasticache.evaluate_elasticache_2(controls.mocks.elasticache["2"].pass)) == 0

test_evaluate_elasticache_2_invalid_input if count(elasticache.evaluate_elasticache_2(controls.mocks.elasticache["2"].fail)) == 2
