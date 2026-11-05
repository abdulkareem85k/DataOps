# Prompt 2 data model

The backend persists the Prompt 2 schema in the existing SQLite database with SQLAlchemy 2. `initialize_database(engine)` imports the model metadata, runs `Base.metadata.create_all(engine)`, and initializes the finding ID counter. The backend startup/health readiness path and `make seed` both call this initializer. This milestone uses `create_all`; it does not introduce Alembic or a managed database.

## Entities

The requested tables are `assessments`, `scope_rules`, `plans`, `plan_steps`, `tool_runs`, `assets`, `services`, `findings`, `evidence`, `approvals`, `audit_events`, `decisions`, `reports`, and `chat_messages`. `finding_sources` is an additional association table so a merged finding can preserve an ordered, separate `tool_run_id` and raw-output locator for each contributing run. `id_counters` stores the SQLite-atomic counter used for `FND-0001`-style finding identifiers.

`Finding` stores the Prompt 2 common fields directly: assessment/title/description/category; optional asset, service, port and web URL/parameter; CVE/CWE arrays; nullable source CVSS vector/score and tool severity; confidence level, numeric confidence and reason; status and validation status; first/last seen and creation time. `Evidence` stores each `observed` or `inference` row independently with content, raw reference and timestamp. `source_tools` in `FindingRead` is derived from linked `ToolRun.tool` values; it is not user-authored or inferred by an LLM.

Pydantic v2 schemas reject unknown fields and constrain the Prompt 2 enumerations and numeric ranges. The data layer does not calculate CVSS/risk, invent CVE/CWE identifiers, fabricate tool output, or merge observed evidence with inference. A finding requires at least one evidence record; nonempty copied vulnerability/severity fields require provenance references. These checks validate shape and linkage, not the truth of external scanner content.

## Repository/service boundary

`AssessmentService`, `ToolRunService`, and `FindingService` coordinate repositories using short-lived SQLAlchemy sessions and transactional operations. `FindingRepository` verifies that the assessment, optional asset/service and every referenced ToolRun belong together before saving the finding, then commits the finding, per-run source refs, and evidence in a single transaction. Finding IDs are allocated by an atomic counter update inside that transaction.

## Raw output

`RawOutputStore` stores bytes under `<DATA_DIR>/raw/<assessment_id>/<tool_run_id>/raw-output.bin`; with the default `DATA_DIR=./data`, the file is in `data/raw/...`. Assessment and ToolRun identifiers are restricted to path-safe characters. The store creates directories with mode `0700`, creates the file with exclusive/no-follow flags, flushes and fsyncs it, changes the file to mode `0400`, computes SHA-256, and returns a path relative to `DATA_DIR`. A second write to the same ToolRun path fails; callers cannot set `raw_output_path` or `sha256` directly through `ToolRunCreate`. Raw bytes are not parsed, modified, served by the application, or emitted to logs. Retention, backup, and external anchoring are outside this milestone.

`backend/tests/fixtures/finding_roundtrip.json` is synthetic test data only. The assessment/finding round-trip tests use temporary SQLite files and synthetic text visibly labeled as a test placeholder; it is not loaded by `make seed`, exposed to Preview, or represented as real assessment evidence. `make seed` creates schema only.
