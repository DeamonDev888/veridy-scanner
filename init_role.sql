-- Initialisation rôle et base
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'demon') THEN
        CREATE ROLE demon WITH LOGIN SUPERUSER;
    END IF;
END $$;
