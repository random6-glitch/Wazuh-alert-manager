/**
 * [CUSTOM ENTITIES] Registry of admin-defined correlation fields.
 *
 * A custom entity maps a raw Wazuh field path (for example
 * data.win.eventdata.targetUserName) to a correlation entity that rules
 * reference as "custom:<id>". The registry is one document in META_INDEX.
 *
 * Data flow:
 *   registry ──► sync_job / backfill ──► extractCustomEntities()
 *            ──► operational alert copy: custom_entities.<id> = [normalized values]
 *            ──► entity_expression.valuesFromAlert() (preview, live queue, bursts)
 *
 * Correlation never reads raw wazuh-alerts documents, so a field becomes usable
 * only after it has been copied into custom_entities by sync or backfill.
 */
import {
  CustomEntityDefinition,
  CustomEntityValueType,
  CUSTOM_ENTITIES_DOC_ID,
  CUSTOM_ENTITY_ID_PATTERN,
  CUSTOM_ENTITY_PATH_PATTERN,
  CUSTOM_ENTITY_PREFIX,
  CUSTOM_ENTITY_VALUE_TYPES,
  MAX_CUSTOM_ENTITIES,
  MAX_CUSTOM_ENTITY_VALUES,
  META_INDEX,
  RULES_INDEX,
} from '../../common';
import { assertManagedWriteTarget } from './index_namespace';
import { normalizeCustomEntityValue, normalizeEntityExpression } from './entity_expression';

const ID = new RegExp(CUSTOM_ENTITY_ID_PATTERN);
const PATH = new RegExp(CUSTOM_ENTITY_PATH_PATTERN);
const MAX_LABEL = 80;
const MAX_DESCRIPTION = 500;
const MAX_IGNORE_VALUES = 20;

/**
 * Shipped registry entries, used until an admin saves the registry for the
 * first time. win_target_user replaces the former built-in entity of the same
 * name; rules that used it are read as custom:win_target_user.
 */
export const DEFAULT_CUSTOM_ENTITIES: CustomEntityDefinition[] = [
  {
    id: 'win_target_user',
    label: 'Windows target user',
    fieldPath: 'data.win.eventdata.targetUserName',
    valueType: 'text_ci',
    ignoreValues: ['-'],
    description: 'Account a Windows Security event acted on (e.g. 4625 logon failure, rule 60122).',
  },
];

export interface CustomEntityRegistryState {
  entities: CustomEntityDefinition[];
  /** False until an admin saves; defaults are served but not yet stored. */
  stored: boolean;
  seqNo?: number;
  primaryTerm?: number;
}

const statusOf = (error: any) => error?.meta?.statusCode || error?.statusCode;

function cleanDefinition(input: any): CustomEntityDefinition {
  const ignoreValues = Array.isArray(input?.ignoreValues) ? input.ignoreValues : [];
  return {
    id: String(input?.id ?? '').trim(),
    label: String(input?.label ?? '').trim(),
    fieldPath: String(input?.fieldPath ?? '').trim(),
    valueType: input?.valueType,
    ignoreValues: Array.from(new Set(ignoreValues.map((value: any) => String(value).trim()).filter(Boolean))) as string[],
    ...(input?.description ? { description: String(input.description).trim() } : {}),
    ...(input?.created_at ? { created_at: input.created_at } : {}),
    ...(input?.created_by ? { created_by: input.created_by } : {}),
    ...(input?.updated_at ? { updated_at: input.updated_at } : {}),
    ...(input?.updated_by ? { updated_by: input.updated_by } : {}),
  };
}

/** Validate one definition (shape only). Returns a list of human-readable errors. */
export function validateCustomEntityDefinition(input: any): string[] {
  const definition = cleanDefinition(input);
  const errors: string[] = [];
  if (!ID.test(definition.id)) {
    errors.push('ID must start with a letter and use only lower-case letters, digits and _ (max 40 characters).');
  }
  if (!definition.label || definition.label.length > MAX_LABEL) errors.push(`Label must contain 1-${MAX_LABEL} characters.`);
  if (!PATH.test(definition.fieldPath)) {
    errors.push('Field path must be a dot path such as data.win.eventdata.targetUserName (max 10 segments).');
  }
  if (!(CUSTOM_ENTITY_VALUE_TYPES as readonly string[]).includes(definition.valueType)) {
    errors.push(`Value type must be one of: ${CUSTOM_ENTITY_VALUE_TYPES.join(', ')}.`);
  }
  if (definition.ignoreValues.length > MAX_IGNORE_VALUES) errors.push(`Use at most ${MAX_IGNORE_VALUES} ignore values.`);
  if ((definition.description || '').length > MAX_DESCRIPTION) errors.push(`Description must be at most ${MAX_DESCRIPTION} characters.`);
  return errors;
}

/** Validate a whole registry: each entry plus uniqueness and size. */
export function validateCustomEntityRegistry(entities: any[]): string[] {
  const errors: string[] = [];
  if (entities.length > MAX_CUSTOM_ENTITIES) errors.push(`At most ${MAX_CUSTOM_ENTITIES} custom entities are allowed.`);
  const ids = new Set<string>();
  for (const entity of entities) {
    for (const error of validateCustomEntityDefinition(entity)) errors.push(`${entity?.id || '?'}: ${error}`);
    const id = String(entity?.id ?? '').trim();
    if (ids.has(id)) errors.push(`Duplicate custom entity ID: ${id}.`);
    ids.add(id);
  }
  return errors;
}

/** Read every value at a dot path, flattening arrays at any level. */
export function readFieldPath(source: any, path: string): unknown[] {
  let current: any[] = [source];
  for (const segment of path.split('.')) {
    const next: any[] = [];
    for (const node of current) {
      if (node == null || typeof node !== 'object') continue;
      const value = node[segment];
      if (Array.isArray(value)) next.push(...value);
      else if (value !== undefined) next.push(value);
    }
    current = next;
    if (!current.length) return [];
  }
  return current.filter((value) => value != null && typeof value !== 'object');
}

/**
 * Build the custom_entities object for one raw alert: id -> sorted, distinct,
 * normalized values (max MAX_CUSTOM_ENTITY_VALUES). Entities with no usable
 * value are omitted, which the evaluator treats as "missing".
 */
export function extractCustomEntities(
  definitions: ReadonlyArray<CustomEntityDefinition>,
  rawSource: any
): Record<string, string[]> {
  const result: Record<string, string[]> = {};
  for (const definition of definitions) {
    const values = Array.from(new Set(
      readFieldPath(rawSource, definition.fieldPath)
        .map((value) => normalizeCustomEntityValue(definition, value))
        .filter((value): value is string => value != null)
    )).sort().slice(0, MAX_CUSTOM_ENTITY_VALUES);
    if (values.length) result[definition.id] = values;
  }
  return result;
}

/** Load the registry. Throws on storage errors (callers decide how to degrade). */
export async function loadCustomEntityRegistry(client: any): Promise<CustomEntityRegistryState> {
  try {
    const result: any = await client.get({ index: META_INDEX, id: CUSTOM_ENTITIES_DOC_ID });
    const source = result?.body?._source || {};
    const entities = Array.isArray(source.entities) ? source.entities.map(cleanDefinition) : [];
    return {
      entities: entities.filter((entity: CustomEntityDefinition) => !validateCustomEntityDefinition(entity).length),
      stored: true,
      seqNo: result?.body?._seq_no,
      primaryTerm: result?.body?._primary_term,
    };
  } catch (error: any) {
    if (statusOf(error) === 404) return { entities: DEFAULT_CUSTOM_ENTITIES.map((entity) => ({ ...entity })), stored: false };
    throw error;
  }
}

/**
 * Sync-safe loader: null on any storage error. Sync then leaves the existing
 * custom_entities untouched instead of overwriting them with an empty object.
 */
export async function loadCustomEntitiesForSync(client: any): Promise<CustomEntityDefinition[] | null> {
  try {
    return (await loadCustomEntityRegistry(client)).entities;
  } catch (error) {
    return null;
  }
}

/** Persist the registry with optimistic concurrency against the state it was loaded from. */
export async function saveCustomEntityRegistry(
  client: any,
  state: CustomEntityRegistryState,
  entities: CustomEntityDefinition[],
  actor: string
): Promise<CustomEntityRegistryState> {
  const errors = validateCustomEntityRegistry(entities);
  if (errors.length) throw Object.assign(new Error(errors[0]), { statusCode: 400, errors });
  const body = {
    entities: entities.map(cleanDefinition),
    updated_at: new Date().toISOString(),
    updated_by: actor,
  };
  const occ = state.stored ? { if_seq_no: state.seqNo, if_primary_term: state.primaryTerm } : { op_type: 'create' };
  try {
    const result: any = await client.index({
      index: assertManagedWriteTarget(META_INDEX),
      id: CUSTOM_ENTITIES_DOC_ID,
      body,
      refresh: 'wait_for',
      ...occ,
    });
    return { entities: body.entities, stored: true, seqNo: result?.body?._seq_no, primaryTerm: result?.body?._primary_term };
  } catch (error: any) {
    if (statusOf(error) === 409) {
      throw Object.assign(new Error('The custom entity registry was changed by someone else. Reload and try again.'), { statusCode: 409 });
    }
    throw error;
  }
}

/** Custom entity ids referenced by one rule document (including retired aliases). */
export function customEntityIdsInRule(rule: any): string[] {
  const expression = normalizeEntityExpression(rule?.trigger?.entityExpression || { groups: [] });
  const ids = new Set<string>();
  for (const group of expression.groups) {
    for (const predicate of group.predicates) {
      if (typeof predicate.entity === 'string' && predicate.entity.startsWith(CUSTOM_ENTITY_PREFIX)) {
        ids.add(predicate.entity.slice(CUSTOM_ENTITY_PREFIX.length));
      }
    }
  }
  return Array.from(ids);
}

/**
 * Map of custom entity id -> names of non-deleted rules that use it. Used to
 * block deleting an entity, or changing its path/type, while rules depend on
 * it (a change would silently alter existing case/dedup keys).
 */
export async function customEntityUsage(client: any): Promise<Record<string, string[]>> {
  const usage: Record<string, string[]> = {};
  const response: any = await client.search({
    index: RULES_INDEX,
    body: {
      size: 10000,
      _source: ['name', 'trigger', 'deleted_at'],
      query: { bool: { must_not: [{ exists: { field: 'document_type' } }] } },
    },
  });
  for (const hit of response?.body?.hits?.hits || []) {
    const rule = hit._source || {};
    if (rule.deleted_at) continue;
    for (const id of customEntityIdsInRule(rule)) {
      (usage[id] = usage[id] || []).push(String(rule.name || hit._id));
    }
  }
  return usage;
}

export const isCustomEntityValueType = (value: any): value is CustomEntityValueType =>
  (CUSTOM_ENTITY_VALUE_TYPES as readonly string[]).includes(value);
