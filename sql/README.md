# SQL Schema & Migrations

- **`lbcpool_schema.sql`**: Consolidated LBRY (`LBC`) mining pool schema and seed data used by `install.sh` for fresh database installations. Contains all table definitions with all historical migrations (2015–2026) already integrated, and seeds only the `lbry` algorithm and initial `mining` state (without legacy altcoin or exchange rows).
- **`2026-11-04-lbc_stratum_widths.sql`** & **`2026-11-15-lbc_seed.sql`**: Idempotent upgrade migrations applied by `install.sh` when upgrading an existing database.
- **`2016-04-03-yaamp.sql.gz`** & **`2015-*.sql` .. `2018-*.sql`**: Historical YiiMP dump and incremental migrations retained for reference.
