package aws.controls.rds

standard_engine(engine) := engine in {"mariadb", "mysql", "oracle-ee", "oracle-ee-cdb", "oracle-se2", "oracle-se2-cdb", "postgres", "sqlserver-ee", "sqlserver-se", "sqlserver-ex", "sqlserver-web"}

disabled_iam_database_authentication(resource) if not resource.configuration.iam_database_authentication_enabled

disabled_iam_database_authentication(resource) if is_null(resource.configuration.iam_database_authentication_enabled)
