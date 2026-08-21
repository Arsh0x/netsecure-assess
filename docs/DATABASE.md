# Database schema notes

The SQLAlchemy schema is PostgreSQL compatible and uses string UUID identifiers for
portable demo data. Foreign keys tie all observations to a project, indexes cover
email, project ownership, asset address, scan state, severity and event timestamps.
SQLite is used by default. Production should use PostgreSQL, Alembic migrations,
encrypted volumes and a dedicated least-privilege database role.

