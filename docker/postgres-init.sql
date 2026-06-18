-- Runs once, on first container start, as the superuser.
--
-- It creates the two roles the migrations expect. The grants are deliberately
-- minimal: if you find yourself adding a privilege here to make something work,
-- that's the signal that something is connecting as the wrong role.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'workbench') THEN
        -- The application. Owns nothing.
        CREATE ROLE workbench LOGIN PASSWORD 'workbench'
            NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'workbench_admin') THEN
        -- Migrations and fixtures. Owns everything, never serves traffic.
        CREATE ROLE workbench_admin LOGIN PASSWORD 'workbench_admin'
            NOSUPERUSER NOCREATEDB NOCREATEROLE;
    END IF;
END
$$;

-- A separate database for the isolation suite, so `make test-db` never touches
-- development data.
SELECT 'CREATE DATABASE workbench_test OWNER workbench_admin'
 WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'workbench_test') \gexec

GRANT ALL PRIVILEGES ON DATABASE workbench TO workbench_admin;
GRANT CONNECT ON DATABASE workbench TO workbench;
GRANT CONNECT ON DATABASE workbench_test TO workbench;
