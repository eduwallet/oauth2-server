# PostgreSQL Integration Guide

This guide explains how to use PostgreSQL as the persistent storage backend for the OAuth2 server.

## Overview

The OAuth2 server now supports three storage backends:
- **Memory**: In-memory storage (default, data lost on restart)
- **SQLite**: File-based SQLite database (single-file persistence)
- **PostgreSQL**: Full-featured PostgreSQL database (production-ready)

## Configuration

### Option 1: Using Docker Compose (Recommended)

The repository includes a complete PostgreSQL setup with Docker Compose:

#### Default (SQLite)
```bash
docker-compose up
```

#### PostgreSQL with Override
```bash
# Using the PostgreSQL override file
docker-compose -f docker-compose.yml -f docker-compose.postgres.yml up
```

#### PostgreSQL with Environment Variables
```bash
# Set database type via environment variable
DB_TYPE=postgres docker-compose up
```

### Option 2: Manual Configuration

1. **Update config.yaml**:
```yaml
database:
  type: "postgres"
  postgres_host: "localhost"
  postgres_port: 5432
  postgres_db: "oauth2"
  postgres_user: "oauth2_user"
  postgres_password: "oauth2_password"
  postgres_sslmode: "disable"  # or "require" for production
  cleanup_interval: 60
```

2. **Start PostgreSQL**:
```bash
# Using Docker
docker run --name oauth2-postgres \
  -e POSTGRES_DB=oauth2 \
  -e POSTGRES_USER=oauth2_user \
  -e POSTGRES_PASSWORD=oauth2_password \
  -p 5432:5432 \
  -d postgres:15-alpine

# Or use existing PostgreSQL instance
```

3. **Run the server**:
```bash
./oauth2-server
```

## Database Schema

The application automatically creates the following tables:

- **auth_codes**: OAuth2 authorization codes with expiration
- **device_codes**: Device flow codes and state
- **dynamic_clients**: Dynamically registered OAuth2 clients  
- **registration_tokens**: Client registration access tokens

All tables include appropriate indexes for performance.

## Environment Variables

You can override database configuration using environment variables:

```bash
# Database type
export DB_TYPE=postgres

# PostgreSQL connection (when using postgres)
export POSTGRES_HOST=localhost
export POSTGRES_PORT=5432
export POSTGRES_DB=oauth2
export POSTGRES_USER=oauth2_user
export POSTGRES_PASSWORD=oauth2_password
export POSTGRES_SSLMODE=disable
```

## Production Considerations

### Security
- Use strong passwords for database users
- Enable SSL/TLS (`postgres_sslmode: "require"`)
- Use connection pooling for high-load scenarios
- Restrict database access to application servers only

### Performance
- Monitor database performance and tune as needed
- Consider read replicas for high-read workloads
- Use connection pooling (pgbouncer, etc.)

### Backup & Recovery
```bash
# Backup
pg_dump -h localhost -U oauth2_user oauth2 > oauth2_backup.sql

# Restore
psql -h localhost -U oauth2_user oauth2 < oauth2_backup.sql
```

### Monitoring
- Monitor connection counts
- Track query performance
- Set up alerts for database health
- Monitor disk space usage

## Migration from SQLite

To migrate existing SQLite data to PostgreSQL:

1. Export SQLite data:
```bash
sqlite3 oauth2.db ".dump" > sqlite_export.sql
```

2. Convert SQLite syntax to PostgreSQL (manual process)

3. Import to PostgreSQL:
```bash
psql -h localhost -U oauth2_user oauth2 < converted_data.sql
```

Note: The application handles schema creation automatically, so focus on migrating data only.

## Troubleshooting

### Common Issues

1. **Connection refused**:
   - Verify PostgreSQL is running
   - Check host/port configuration
   - Verify network connectivity

2. **Authentication failed**:
   - Check username/password
   - Verify user exists and has permissions
   - Check PostgreSQL pg_hba.conf

3. **Database does not exist**:
   - Create database manually: `createdb -U postgres oauth2`
   - Or let PostgreSQL auto-create via Docker environment

4. **SSL/TLS issues**:
   - Start with `sslmode=disable` for testing
   - Configure proper certificates for production

### Logging

Enable debug logging to troubleshoot database issues:
```yaml
logging:
  level: "debug"
```

### Health Checks

The server includes health checks that verify database connectivity:
```bash
curl http://localhost:8080/health
```

## Performance Comparison

| Storage Type | Persistence | Performance | Scalability | Use Case |
|-------------|-------------|-------------|-------------|----------|
| Memory      | No          | Fastest     | Single node | Development |
| SQLite      | Yes         | Fast        | Single node | Small/Medium production |
| PostgreSQL  | Yes         | Good        | Horizontal  | Large production |

Choose PostgreSQL for:
- Production environments
- High availability requirements  
- Multiple server instances
- Advanced querying needs
- Compliance/audit requirements
