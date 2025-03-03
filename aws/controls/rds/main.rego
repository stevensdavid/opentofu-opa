package aws.controls.rds

evaluate(plan) := union({evaluate_rds_1(plan), evaluate_rds_2(plan)})
