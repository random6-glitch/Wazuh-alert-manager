// [CUSTOM ENTITIES] Backfill tests.
import { backfillCustomEntities } from './custom_entity_backfill';
import { DEFAULT_CUSTOM_ENTITIES } from './custom_entities';

const projected = (id: string, sourceId: string | null) => ({
  _index: 'wazuh-alert-status-v2-000001',
  _id: id,
  _source: sourceId ? { source_index: 'wazuh-alerts-4.x-2026.10.18', source_id: sourceId } : {},
  sort: ['2026-10-18T14:00:00.000Z', id],
});

describe('custom entity backfill', () => {
  test('reads only registry paths from raw alerts and partially updates custom_entities', async () => {
    const client: any = {
      search: jest.fn()
        .mockResolvedValueOnce({ body: { hits: { hits: [projected('a', 'raw-a'), projected('b', 'raw-b'), projected('c', null)] } } }),
      mget: jest.fn().mockResolvedValue({ body: { docs: [
        { found: true, _source: { data: { win: { eventdata: { targetUserName: 'Administrator' } } } } },
        { found: false },
      ] } }),
      bulk: jest.fn().mockResolvedValue({ body: { items: [{ update: { status: 200 } }] } }),
      indices: { refresh: jest.fn().mockResolvedValue({}) },
    };

    const result = await backfillCustomEntities(client, DEFAULT_CUSTOM_ENTITIES, {
      hours: 24, now: new Date('2026-10-19T12:00:00.000Z'),
    });

    expect(result).toEqual({ hours: 24, scanned: 3, updated: 1, missingSource: 2, failed: 0, truncated: false });
    expect(client.search.mock.calls[0][0].body.query.bool.filter[0].range['@timestamp'].gte).toBe('2026-10-18T12:00:00.000Z');
    expect(client.mget.mock.calls[0][0].body.docs[0]).toEqual({
      _index: 'wazuh-alerts-4.x-2026.10.18', _id: 'raw-a', _source: ['data.win.eventdata.targetUserName'],
    });
    expect(client.bulk.mock.calls[0][0].body).toEqual([
      { update: { _index: 'wazuh-alert-status-v2-000001', _id: 'a', retry_on_conflict: 3 } },
      { doc: { custom_entities: { win_target_user: ['administrator'] } } },
    ]);
    expect(client.indices.refresh).toHaveBeenCalled();
  });

  test('stops at the alert cap, reports truncation, and clamps the window', async () => {
    const page = Array.from({ length: 2 }, (_, i) => projected(`p${i}`, `raw-${i}`));
    const client: any = {
      search: jest.fn().mockResolvedValue({ body: { hits: { hits: page } } }),
      mget: jest.fn().mockResolvedValue({ body: { docs: page.map(() => ({ found: true, _source: {} })) } }),
      bulk: jest.fn().mockResolvedValue({ body: { items: page.map(() => ({ update: { status: 500 } })) } }),
    };
    const result = await backfillCustomEntities(client, DEFAULT_CUSTOM_ENTITIES, { hours: 9999, maxAlerts: 2 });
    expect(result).toMatchObject({ hours: 168, scanned: 2, failed: 2, truncated: true });
  });
});
