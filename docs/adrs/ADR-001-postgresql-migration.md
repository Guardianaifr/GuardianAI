# ADR-001: PostgreSQL Migration

## Status
Proposed

## Context
The GuardianAI platform currently uses SQLite as the primary database for both backend metadata (e.g., identity gates, telemetry) and local testing. While SQLite is suitable for early development and low-concurrency environments, as GuardianAI prepares for a high-throughput production launch with advanced security controls and higher concurrency demands, SQLite presents limitations (e.g., database locks, lack of distributed scalability, limited concurrent writes). We need a robust, production-grade relational database.

## Decision
We will migrate the primary database from SQLite to PostgreSQL. 
PostgreSQL will be used as the standard relational database engine for all production deployments.

## Consequences
- **Positive:** Better concurrency, robust transactional integrity, native support for advanced data types (e.g., JSONB), and scalability.
- **Negative:** Increased operational overhead for deployments (requiring a separate database service rather than a local file) and potential necessity to rewrite SQLite-specific queries or migrations.
- **Risks:** Data migration risk from existing SQLite instances; developers will need to run a local PostgreSQL instance or Docker container for testing.
