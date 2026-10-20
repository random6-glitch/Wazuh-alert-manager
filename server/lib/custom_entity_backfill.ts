/**
 * [CUSTOM ENTITIES] Re-compute custom_entities for alerts already synced.
 *
 * Sync only fills custom_entities for alerts it copies after a registry
 * change. This walks the operational alert copies in the last N hours, reads
 * just the registry's field paths from each raw wazuh-alerts document
 * (source_index/source_id), and partially updates custom_entities. No other
 * field is touched, so triage state (status, case, assignment) is safe.
 */
import {
  ALERTS_READ_ALIAS,
  CustomEntityBackfillResult,
  CustomEntityDefinition,
  MAX_CUSTOM_ENTITY_BACKFILL_ALERTS,
  MAX_CUSTOM_ENTITY_BACKFILL_HOURS,
} from '../../common';
import { assertManagedWriteTarget } from './index_namespace';
import { extractCustomEntities } from './custom_entities';

const PAGE_SIZE = 500;

export interface BackfillOptions {
  hours: number;
  now?: Date;
  maxAlerts?: number;
}

export async function backfillCustomEntities(
  client: any,
  definitions: ReadonlyArray<CustomEntityDefinition>,
  options: BackfillOptions
): Promise<CustomEntityBackfillResult> {
  const hours = Math.max(1, Math.min(MAX_CUSTOM_ENTITY_BACKFILL_HOURS, Math.round(options.hours)));
  const maxAlerts = Math.max(1, Math.min(MAX_CUSTOM_ENTITY_BACKFILL_ALERTS, options.maxAlerts ?? MAX_CUSTOM_ENTITY_BACKFILL_ALERTS));
  const now = options.now || new Date();
  const from = new Date(now.getTime() - hours * 3600000).toISOString();
  // Fetch only the configured paths from raw alerts; never the whole document.
  const includes = Array.from(new Set(definitions.map((definition) => definition.fieldPath)));
  const result: CustomEntityBackfillResult = { hours, scanned: 0, updated: 0, missingSource: 0, failed: 0, truncated: false };
  let searchAfter: any[] | undefined;

  for (;;) {
    const size = Math.min(PAGE_SIZE, maxAlerts - result.scanned);
    if (size <= 0) {
      result.truncated = true;
      break;
    }
    const page: any = await client.search({
      index: ALERTS_READ_ALIAS,
      body: {
        size,
        _source: ['source_index', 'source_id'],
        sort: [{ '@timestamp': 'desc' }, { alert_uid: 'desc' }],
        ...(searchAfter ? { search_after: searchAfter } : {}),
        query: { bool: { filter: [{ range: { '@timestamp': { gte: from, lte: now.toISOString() } } }] } },
      },
    });
    const hits: any[] = page?.body?.hits?.hits || [];
    if (!hits.length) break;
    result.scanned += hits.length;
    searchAfter = hits[hits.length - 1].sort;

    const withSource = hits.filter((hit) => hit._source?.source_index && hit._source?.source_id);
    result.missingSource += hits.length - withSource.length;
    if (!withSource.length) continue;

    const raw: any = await client.mget({
      body: {
        docs: withSource.map((hit) => ({
          _index: hit._source.source_index,
          _id: hit._source.source_id,
          _source: includes.length ? includes : false,
        })),
      },
    });
    const docs: any[] = raw?.body?.docs || [];
    const body: any[] = [];
    withSource.forEach((hit, position) => {
      const doc = docs[position];
      if (!doc?.found) {
        // Raw alert rotated out of wazuh-alerts-*; keep whatever is stored.
        result.missingSource += 1;
        return;
      }
      body.push({ update: { _index: assertManagedWriteTarget(hit._index), _id: hit._id, retry_on_conflict: 3 } });
      body.push({ doc: { custom_entities: extractCustomEntities(definitions, doc._source || {}) } });
    });
    if (!body.length) continue;
    const bulk: any = await client.bulk({ body });
    for (const item of bulk?.body?.items || []) {
      const status = item?.update?.status;
      if (status >= 200 && status < 300) result.updated += 1;
      else result.failed += 1;
    }
    if (hits.length < size) break;
  }
  if (client.indices?.refresh) {
    try {
      await client.indices.refresh({ index: ALERTS_READ_ALIAS });
    } catch (error) {
      // Visibility catches up on the next periodic refresh.
    }
  }
  return result;
}
