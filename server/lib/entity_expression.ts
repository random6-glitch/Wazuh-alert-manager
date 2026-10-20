import {
  BuiltinCorrelationEntity,
  CorrelationEntity,
  CorrelationEntityExpression,
  CustomEntityDefinition,
  CustomEntityValueType,
  CORRELATION_ENTITIES,
  CUSTOM_ENTITY_ID_PATTERN,
  CUSTOM_ENTITY_PREFIX,
  LEGACY_ENTITY_ALIASES,
  MAX_CUSTOM_ENTITY_VALUE_LENGTH,
} from '../../common';

export const MAX_ENTITY_GROUPS = 5;
export const MAX_ENTITY_PREDICATES = 5;

const ENTITIES: readonly BuiltinCorrelationEntity[] = CORRELATION_ENTITIES;
const CUSTOM_ID = new RegExp(CUSTOM_ENTITY_ID_PATTERN);

// [CUSTOM ENTITIES] Optional registry passed in by callers that have loaded it
// (rule save/preview routes, sync). Pure evaluation does not need it, because
// custom values are already normalized where they are produced.
export type CustomEntityRegistry = ReadonlyArray<CustomEntityDefinition> | null | undefined;

export function isBuiltinEntity(entity: unknown): entity is BuiltinCorrelationEntity {
  return typeof entity === 'string' && (ENTITIES as readonly string[]).includes(entity);
}

/** [CUSTOM ENTITIES] True for a well-formed "custom:<id>" reference (registry membership is checked separately). */
export function isCustomEntity(entity: unknown): entity is `custom:${string}` {
  return typeof entity === 'string' && entity.startsWith(CUSTOM_ENTITY_PREFIX) &&
    CUSTOM_ID.test(entity.slice(CUSTOM_ENTITY_PREFIX.length));
}

export function customEntityId(entity: string): string {
  return entity.slice(CUSTOM_ENTITY_PREFIX.length);
}

/** [CUSTOM ENTITIES] Map retired built-in ids (win_target_user) to their registry reference. */
export function resolveEntityAlias(entity: any): any {
  return typeof entity === 'string' && LEGACY_ENTITY_ALIASES[entity] ? LEGACY_ENTITY_ALIASES[entity] : entity;
}

function findDefinition(registry: CustomEntityRegistry, entity: string): CustomEntityDefinition | undefined {
  if (!registry || !isCustomEntity(entity)) return undefined;
  const id = customEntityId(entity);
  return registry.find((definition) => definition.id === id);
}

function canonicalIpv4(value: string): string | null {
  const parts = value.split('.');
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part))) return null;
  const numbers = parts.map(Number);
  if (numbers.some((part) => part > 255)) return null;
  return numbers.join('.');
}

function canonicalIpv6(value: string): string | null {
  if (!/^[0-9a-f:.]+$/i.test(value) || value.indexOf(':') < 0) return null;
  let source = value.toLowerCase();
  const lastColon = source.lastIndexOf(':');
  const dotted = source.slice(lastColon + 1);
  if (dotted.indexOf('.') >= 0) {
    const ipv4 = canonicalIpv4(dotted);
    if (!ipv4) return null;
    const bytes = ipv4.split('.').map(Number);
    source = `${source.slice(0, lastColon)}:${((bytes[0] << 8) | bytes[1]).toString(16)}:${(
      (bytes[2] << 8) |
      bytes[3]
    ).toString(16)}`;
  }

  if ((source.match(/::/g) || []).length > 1) return null;
  const halves = source.split('::');
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  if ([...left, ...right].some((part) => !/^[0-9a-f]{1,4}$/.test(part))) return null;
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) return null;
  const words = [...left, ...Array(missing).fill('0'), ...right].map((part) => parseInt(part, 16));
  if (words.length !== 8) return null;

  let bestStart = -1;
  let bestLength = 0;
  for (let start = 0; start < words.length; start += 1) {
    if (words[start] !== 0) continue;
    let end = start;
    while (end < words.length && words[end] === 0) end += 1;
    if (end - start > bestLength && end - start >= 2) {
      bestStart = start;
      bestLength = end - start;
    }
    start = end - 1;
  }
  const rendered = words.map((word) => word.toString(16));
  if (bestStart < 0) return rendered.join(':');
  const before = rendered.slice(0, bestStart).join(':');
  const after = rendered.slice(bestStart + bestLength).join(':');
  return `${before}::${after}`;
}

/** Normalize a raw value by value type. Shared by built-in and custom entities. */
export function normalizeTypedValue(valueType: CustomEntityValueType, input: unknown): string | null {
  if (input == null || typeof input === 'object') return null;
  const value = String(input).trim();
  if (!value) return null;
  if (valueType === 'ip') return canonicalIpv4(value) || canonicalIpv6(value);
  if (valueType === 'port') {
    if (!/^\d+$/.test(value)) return null;
    const port = Number(value);
    return Number.isInteger(port) && port >= 0 && port <= 65535 ? String(port) : null;
  }
  if (value.length > MAX_CUSTOM_ENTITY_VALUE_LENGTH) return null;
  return valueType === 'text_ci' ? value.toLowerCase() : value;
}

/**
 * [CUSTOM ENTITIES] Normalize one value of a custom entity: type normalization,
 * then the definition's ignore list (e.g. Windows "-"), compared after the same
 * normalization so "-", " - " and case variants are all ignored.
 */
export function normalizeCustomEntityValue(definition: CustomEntityDefinition, input: unknown): string | null {
  const value = normalizeTypedValue(definition.valueType, input);
  if (value == null) return null;
  const ignored = (definition.ignoreValues || [])
    .map((entry) => normalizeTypedValue(definition.valueType, entry))
    .filter((entry): entry is string => entry != null);
  return ignored.includes(value) ? null : value;
}

/** Normalize values identically for persistence, preview, live matching, and identity keys. */
export function normalizeEntityValue(
  entity: CorrelationEntity,
  input: unknown,
  registry?: CustomEntityRegistry
): string | null {
  if (input == null) return null;
  // [CUSTOM ENTITIES] With a registry (rule save/preview) apply the entity's
  // own type and ignore list. Without one (live evaluation) values were
  // already normalized when stored, so only trimming is applied.
  if (isCustomEntity(entity)) {
    const definition = findDefinition(registry, entity);
    if (definition) return normalizeCustomEntityValue(definition, input);
    const value = String(input).trim();
    return value || null;
  }
  const value = String(input).trim();
  if (!value) return null;
  if (entity === 'srcip' || entity === 'dstip') return normalizeTypedValue('ip', value);
  if (entity === 'srcport' || entity === 'dstport') return normalizeTypedValue('port', value);
  if (entity === 'user' || entity === 'dstuser' || entity === 'process') return value.toLowerCase();
  return value;
}

const isKnownEntity = (entity: unknown) => isBuiltinEntity(entity) || isCustomEntity(entity);

export function normalizeEntityExpression(input: any, registry?: CustomEntityRegistry): CorrelationEntityExpression {
  const groups = Array.isArray(input?.groups) ? input.groups : [];
  return {
    version: 1,
    groups: groups
      .map((group: any) => ({
        ...group,
        predicates: (Array.isArray(group?.predicates) ? group.predicates : [])
          // [CUSTOM ENTITIES] Rewrite retired built-in ids on every read, so
          // rules saved as "win_target_user" keep working as
          // "custom:win_target_user" without a stored-data migration.
          .map((predicate: any) => ({ ...predicate, entity: resolveEntityAlias(predicate?.entity) }))
          .map((predicate: any) => ({
            ...predicate,
            operator: predicate?.operator || 'equals',
            ...(predicate?.operator === 'exists'
              ? { value: undefined }
              : { value: isKnownEntity(predicate?.entity)
              ? normalizeEntityValue(predicate.entity, predicate.value, registry) ?? ''
              : typeof predicate?.value === 'string'
              ? predicate.value.trim()
              : predicate?.value }),
          }))
          .sort((a: any, b: any) => a.order - b.order),
      }))
      .sort((a: any, b: any) => a.order - b.order),
  };
}

/**
 * Validate structure and entities. [CUSTOM ENTITIES] When a registry is given
 * (rule save, preview, rollback) every custom entity must exist in it; without
 * one only the "custom:<id>" format is checked.
 */
export function validateEntityExpression(
  expression: CorrelationEntityExpression,
  registry?: CustomEntityRegistry
): string[] {
  const errors: string[] = [];
  const groups: any[] = Array.isArray(expression?.groups) ? expression.groups : [];
  const predicates: any[] = ([] as any[]).concat(...groups.map((group) => group.predicates || []));
  if (expression?.version !== 1) errors.push('Entity expression version must be 1.');
  if (groups.length > MAX_ENTITY_GROUPS) errors.push('Entity expression cannot contain more than 5 groups.');
  if (predicates.length > MAX_ENTITY_PREDICATES) {
    errors.push('Entity expression cannot contain more than 5 predicates in total.');
  }
  const groupIds = new Set<string>();
  const groupOrders = new Set<number>();
  const predicateIds = new Set<string>();
  const predicateKeys = new Set<string>();
  for (const group of groups) {
    if (!group.id || typeof group.id !== 'string' || group.id.trim() !== group.id) {
      errors.push('Each entity group needs a non-blank stable ID.');
    } else if (groupIds.has(group.id)) errors.push(`Duplicate entity group ID: ${group.id}.`);
    else groupIds.add(group.id);
    if (!Number.isInteger(group.order) || group.order < 0) errors.push(`Entity group ${group.id || '?'} needs a non-negative integer order.`);
    else if (groupOrders.has(group.order)) errors.push(`Duplicate entity group order: ${group.order}.`);
    else groupOrders.add(group.order);
    if (!Array.isArray(group.predicates) || group.predicates.length === 0) {
      errors.push(`Entity group ${group.id || '?'} needs at least one predicate.`);
      continue;
    }
    const orders = new Set<number>();
    for (const predicate of group.predicates) {
      if (!predicate.id || typeof predicate.id !== 'string' || predicate.id.trim() !== predicate.id) {
        errors.push('Each entity predicate needs a non-blank stable ID.');
      } else if (predicateIds.has(predicate.id)) errors.push(`Duplicate entity predicate ID: ${predicate.id}.`);
      else predicateIds.add(predicate.id);
      if (!Number.isInteger(predicate.order) || predicate.order < 0) {
        errors.push(`Entity predicate ${predicate.id || '?'} needs a non-negative integer order.`);
      } else if (orders.has(predicate.order)) errors.push(`Duplicate predicate order in group ${group.id || '?'}: ${predicate.order}.`);
      else orders.add(predicate.order);
      if (!isKnownEntity(predicate.entity)) errors.push(`Entity predicate ${predicate.id || '?'} has an invalid entity.`);
      else if (registry && isCustomEntity(predicate.entity) && !findDefinition(registry, predicate.entity)) {
        errors.push(`Entity predicate ${predicate.id || '?'} uses custom entity "${customEntityId(predicate.entity)}", which is not defined.`);
      }
      if (predicate.operator !== 'exists' && predicate.operator !== 'equals') {
        errors.push(`Entity predicate ${predicate.id || '?'} has an invalid operator.`);
      }
      const normalized = predicate.operator === 'exists'
        ? ''
        : isKnownEntity(predicate.entity)
        ? normalizeEntityValue(predicate.entity, predicate.value, registry)
        : null;
      if (predicate.operator === 'equals' && normalized == null) errors.push(`Entity predicate ${predicate.id || '?'} has an invalid or blank value.`);
      else {
        const key = `${predicate.entity}\u0000${predicate.operator}\u0000${normalized}`;
        if (predicateKeys.has(key)) errors.push(`Duplicate entity predicate: ${predicate.entity}:${predicate.operator}:${normalized}.`);
        else predicateKeys.add(key);
      }
    }
  }
  return errors;
}

function valuesFromAlert(entity: CorrelationEntity, alert: any): unknown[] {
  const data = alert?.data && typeof alert.data === 'object' ? alert.data : {};
  let value: any;
  // [CUSTOM ENTITIES] Custom values live in the projected custom_entities
  // object, written by sync/backfill from the registry's fieldPath.
  if (isCustomEntity(entity)) {
    const stored = alert?.custom_entities && typeof alert.custom_entities === 'object' ? alert.custom_entities : {};
    value = stored[customEntityId(entity)];
    return Array.isArray(value) ? value : value == null ? [] : [value];
  }
  switch (entity) {
    case 'srcip': value = data.srcip; break;
    case 'dstip': value = data.dstip; break;
    case 'srcport': value = data.srcport; break;
    case 'dstport': value = data.dstport; break;
    case 'user': value = data.srcuser; break;
    case 'dstuser': value = data.dstuser; break;
    case 'process': value = data?.process?.name ?? data?.process; break;
    case 'agent': value = alert?.agent?.name; break;
  }
  return Array.isArray(value) ? value : value == null ? [] : [value];
}

export interface MatchingEntityGroup {
  groupId: string;
  order: number;
  values: Array<{ predicateId: string; entity: CorrelationEntity; value: string }>;
}

export interface EntityExpressionMatch {
  matched: boolean;
  matchingGroups: MatchingEntityGroup[];
}

/** Shared in-memory evaluator for preview and live execution. */
export function evaluateEntityExpression(
  expression: CorrelationEntityExpression,
  alert: any
): EntityExpressionMatch {
  if (!expression.groups?.length) return { matched: true, matchingGroups: [] };
  const matchingGroups: MatchingEntityGroup[] = [];
  const groups = (expression.groups || []).slice().sort((a, b) => a.order - b.order);
  for (const group of groups) {
    const values: MatchingEntityGroup['values'] = [];
    let matches = true;
    const predicates = (group.predicates || []).slice().sort((a, b) => a.order - b.order);
    for (const predicate of predicates) {
      const actual = valuesFromAlert(predicate.entity, alert)
        .map((value) => normalizeEntityValue(predicate.entity, value))
        .filter((value): value is string => value != null)
        .sort();
      const expected = predicate.operator === 'equals'
        ? normalizeEntityValue(predicate.entity, predicate.value)
        : actual[0] || null;
      if (expected == null || actual.indexOf(expected) < 0) {
        matches = false;
        break;
      }
      values.push({ predicateId: predicate.id, entity: predicate.entity, value: expected });
    }
    if (matches && values.length === predicates.length && values.length > 0) {
      matchingGroups.push({ groupId: group.id, order: group.order, values });
    }
  }
  return { matched: matchingGroups.length > 0, matchingGroups };
}

/** Stable structural identity component; callers prepend the rule ID and routing scope. */
export function matchingEntityGroupIdentity(group: MatchingEntityGroup): string {
  return JSON.stringify([
    group.groupId,
    group.order,
    group.values.map((value) => [value.predicateId, value.entity, value.value]),
  ]);
}
