export const PLUGIN_ID = 'wazuhAlertManager';
export const PLUGIN_NAME = 'wazuh-alert-manager';

// v2 storage keeps the install-and-go permissions profile of older releases
// while remaining disjoint from Wazuh's native `wazuh-alerts-*` family.
// Write validation uses these exact prefixes; never broaden them to
// `wazuh-alert*` or add a native Wazuh index.
export const MANAGED_INDEX_PREFIXES = [
  'wazuh-alert-status-v2-',
  'wazuh-alert-manager-v2-',
] as const;

export const ALERTS_READ_ALIAS = 'wazuh-alert-status-v2-read';
export const ALERTS_WRITE_ALIAS = 'wazuh-alert-status-v2-write';
// Numeric rollover generations only. Carry-forward staging indices deliberately
// sit outside these templates until an atomic alias cutover.
export const ALERTS_INDEX_PATTERN = 'wazuh-alert-status-v2-0*';
export const ALERTS_INITIAL_INDEX = 'wazuh-alert-status-v2-000001';

export const ACTIVITY_READ_ALIAS = 'wazuh-alert-manager-v2-activity-read';
export const ACTIVITY_WRITE_ALIAS = 'wazuh-alert-manager-v2-activity-write';
export const ACTIVITY_INDEX_PATTERN = 'wazuh-alert-manager-v2-activity-0*';
export const ACTIVITY_INITIAL_INDEX = 'wazuh-alert-manager-v2-activity-000001';

// Rollable case-evidence relationship family. One bounded document per
// case-alert link: archive location, provenance, lifecycle state, optional
// hold, and a compact snapshot sufficient for case context and attack-path
// reconstruction when the full alert is archived or purged.
export const EVIDENCE_READ_ALIAS = 'wazuh-alert-manager-v2-evidence-read';
export const EVIDENCE_WRITE_ALIAS = 'wazuh-alert-manager-v2-evidence-write';
export const EVIDENCE_INDEX_PATTERN = 'wazuh-alert-manager-v2-evidence-0*';
export const EVIDENCE_INITIAL_INDEX = 'wazuh-alert-manager-v2-evidence-000001';

// ALERT_STATUS_INDEX remains as a compatibility symbol for route code while
// its value is now the v2 read alias. New code should prefer the explicit alias.
export const ALERT_STATUS_INDEX = ALERTS_READ_ALIAS;
export const COMMENTS_INDEX = ACTIVITY_READ_ALIAS;

// Cases are alias-backed like the other v2 families. Reads go through the read
// alias (every retained generation is searchable); writes go through the write
// alias (a single numeric generation). CASES_INDEX is the read alias so existing
// case reads keep working; writes must use CASES_WRITE_ALIAS.
export const CASES_READ_ALIAS = 'wazuh-alert-manager-v2-cases-read';
export const CASES_WRITE_ALIAS = 'wazuh-alert-manager-v2-cases-write';
export const CASES_INDEX_PATTERN = 'wazuh-alert-manager-v2-cases-0*';
export const CASES_INITIAL_INDEX = 'wazuh-alert-manager-v2-cases-000001';
// Pre-alias v2 singleton, retained read-only after the cases alias migration.
export const CASES_V2_SINGLETON_INDEX = 'wazuh-alert-manager-v2-cases';
export const CASES_INDEX = CASES_READ_ALIAS;

export const META_INDEX = 'wazuh-alert-manager-v2-meta';
export const RULES_INDEX = 'wazuh-alert-manager-v2-rules';
export const MIGRATION_INDEX = 'wazuh-alert-manager-v2-migration';
export const SYNC_DLQ_INDEX = 'wazuh-alert-manager-v2-sync-dlq';
export const AUTOMATION_QUEUE_INDEX = 'wazuh-alert-manager-v2-automation-queue';
export const AUTOMATION_DLQ_INDEX = 'wazuh-alert-manager-v2-automation-dlq';
export const AUTOMATION_EXECUTIONS_INDEX = 'wazuh-alert-manager-v2-automation-executions';
export const AUTOMATION_RULESET_SNAPSHOT_PREFIX = 'automation-ruleset:';
export const AUTOMATION_SETTINGS_DOC_ID = 'automation-settings';
export const AUTOMATION_WORKER_LEASE_ID = 'automation-worker-lease';
export const AUTOMATION_DEFAULT_MAX_BACKLOG = 10000;
export const AUTOMATION_DEFAULT_MAX_DEFERRED = 50000;
export const AUTOMATION_MAX_ENABLED_RULES = 200;
export const AUTOMATION_MAX_RULE_SNAPSHOT_BYTES = 1024 * 1024;
export const AUTOMATION_ADMISSION_RECONCILE_BATCH = 100;
export const AUTOMATION_BULK_MAX_ACTIONS = 500;
export const AUTOMATION_BULK_MAX_BYTES = 5 * 1024 * 1024;

// Read-only migration inputs. They are never provisioned, mapped, deleted, or
// targeted by normal v2 writes.
export const LEGACY_ALERT_STATUS_INDEX = 'wazuh-alert-status';
export const LEGACY_COMMENTS_INDEX = 'wazuh-alert-manager-comments';
export const LEGACY_CASES_INDEX = 'wazuh-alert-manager-cases';
export const LEGACY_META_INDEX = 'wazuh-alert-manager-meta';
export const LEGACY_RULES_INDEX = 'wazuh-alert-manager-rules';

export const API_ROOT = '/api/wazuh_alert_manager';

export const ALERT_STATUSES = ['open', 'in_progress', 'closed'] as const;

export const CASE_SEVERITIES = ['low', 'medium', 'high', 'critical'] as const;

export const CASE_STATUSES = ['open', 'in_progress', 'closed'] as const;

export const AI_PROVIDERS = ['openai', 'deepseek', 'gemini', 'anthropic'] as const;

export const AI_SETTINGS_DOC_ID = 'ai_settings';

// Correlation rules: entity types an alert can be grouped by, and the ceiling
// on how many cases one evaluation pass may auto-create (blast-radius guard).
// Built-in entities only. Custom entities ("custom:<id>") are validated
// against the registry; see the CUSTOM ENTITIES constants below.
export const CORRELATION_ENTITIES = [
  'agent', 'srcip', 'dstip', 'srcport', 'dstport', 'user', 'dstuser', 'process',
] as const;
export const MAX_AUTO_CASES_PER_RUN = 20;

// [CUSTOM ENTITIES] Registry of admin-defined correlation fields.
// Stored as one document in META_INDEX, like sync and AI settings.
export const CUSTOM_ENTITIES_DOC_ID = 'custom_entities';
export const CUSTOM_ENTITY_PREFIX = 'custom:';
export const MAX_CUSTOM_ENTITIES = 20;
/** Lower-case slug, starts with a letter, max 40 chars. */
export const CUSTOM_ENTITY_ID_PATTERN = '^[a-z][a-z0-9_]{0,39}$';
/** Dot path of up to 10 segments; segments allow letters, digits, _ - @. */
export const CUSTOM_ENTITY_PATH_PATTERN = '^[A-Za-z0-9_@-]{1,64}(\\.[A-Za-z0-9_@-]{1,64}){0,9}$';
export const CUSTOM_ENTITY_VALUE_TYPES = ['text_ci', 'text', 'ip', 'port'] as const;
/** At most this many distinct values are kept per entity per alert. */
export const MAX_CUSTOM_ENTITY_VALUES = 10;
export const MAX_CUSTOM_ENTITY_VALUE_LENGTH = 256;
export const MAX_CUSTOM_ENTITY_BACKFILL_HOURS = 168;
export const MAX_CUSTOM_ENTITY_BACKFILL_ALERTS = 50000;
// [CUSTOM ENTITIES] The former built-in "win_target_user" entity, now shipped
// as a pre-defined registry entry. Rules saved with the old id are read as
// "custom:win_target_user" (see normalizeEntityExpression).
export const LEGACY_ENTITY_ALIASES: Record<string, string> = {
  win_target_user: 'custom:win_target_user',
};

