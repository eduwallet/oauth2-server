-- PostgreSQL initialization script for OAuth2 server
-- This script runs when the PostgreSQL container starts for the first time

-- Enable necessary extensions (if needed in the future)
-- CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create indexes will be handled by the application migration
-- This script is mainly for any initial data or setup

-- Optional: Create a read-only user for monitoring/reporting
-- CREATE USER oauth2_reader WITH PASSWORD 'readonly_password';
-- GRANT SELECT ON ALL TABLES IN SCHEMA public TO oauth2_reader;
-- GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO oauth2_reader;

-- The application will handle table creation via migrations
COMMENT ON DATABASE oauth2 IS 'OAuth2 Server Database - Contains authorization codes, device codes, dynamic clients, and registration tokens';
