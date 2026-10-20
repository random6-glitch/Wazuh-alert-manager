// [CUSTOM ENTITIES] Registry library tests.
import { CUSTOM_ENTITIES_DOC_ID, META_INDEX } from '../../common';
import {
  customEntityIdsInRule,
  customEntityUsage,
  DEFAULT_CUSTOM_ENTITIES,
  extractCustomEntities,
  loadCustomEntitiesForSync,
  loadCustomEntityRegistry,
  readFieldPath,
  saveCustomEntityRegistry,
  validateCustomEntityDefinition,
  validateCustomEntityRegistry,
} from './custom_entities';

const definition = (patch: any = {}) => ({
  id: 'logon_ip',
  label: 'Logon IP',
  fieldPath: 'data.win.eventdata.ipAddress',
  valueType: 'ip',
  ignoreValues: ['::1', '127.0.0.1'],
  ...patch,
});

describe('custom entity registry', () => {
  test('reads dot paths, flattening arrays and dropping objects', () => {
    const source = { data: { users: ['a', 'b'], nested: [{ name: 'x' }, { name: 'y' }], obj: { k: 1 } } };
    expect(readFieldPath(source, 'data.users')).toEqual(['a', 'b']);
    expect(readFieldPath(source, 'data.nested.name')).toEqual(['x', 'y']);
    expect(readFieldPath(source, 'data.obj')).toEqual([]);
    expect(readFieldPath(source, 'data.missing.path')).toEqual([]);
  });

  test('extracts normalized, distinct, sorted values and skips ignored or empty ones', () => {
    const source = { data: { win: { eventdata: { ipAddress: ['010.0.0.9', '10.0.0.5', '10.0.0.9', '::1'], targetUserName: '-' } } } };
    expect(extractCustomEntities([definition(), DEFAULT_CUSTOM_ENTITIES[0]], source)).toEqual({ logon_ip: ['10.0.0.5', '10.0.0.9'] });
  });

  test('validates definitions and whole registries', () => {
    expect(validateCustomEntityDefinition(definition())).toEqual([]);
    expect(validateCustomEntityDefinition(definition({ id: '9bad', fieldPath: 'data..x', valueType: 'blob', label: '' }))).toHaveLength(4);
    expect(validateCustomEntityRegistry([definition(), definition()])).toContain('Duplicate custom entity ID: logon_ip.');
    expect(validateCustomEntityRegistry(Array.from({ length: 21 }, (_, i) => definition({ id: `e${i}` })))).toContain(
      'At most 20 custom entities are allowed.'
    );
  });

  test('serves the shipped defaults until the registry is first saved', async () => {
    const client = { get: jest.fn().mockRejectedValue({ meta: { statusCode: 404 } }) };
    const state = await loadCustomEntityRegistry(client);
    expect(state.stored).toBe(false);
    expect(state.entities.map((entity) => entity.id)).toEqual(['win_target_user']);
    expect(client.get).toHaveBeenCalledWith({ index: META_INDEX, id: CUSTOM_ENTITIES_DOC_ID });
  });

  test('sync loader degrades to null on storage errors instead of an empty registry', async () => {
    expect(await loadCustomEntitiesForSync({ get: jest.fn().mockRejectedValue({ meta: { statusCode: 503 } }) })).toBeNull();
  });

  test('saves with create-once, then optimistic concurrency, and maps conflicts to 409', async () => {
    const client: any = { index: jest.fn().mockResolvedValue({ body: { _seq_no: 4, _primary_term: 1 } }) };
    const saved = await saveCustomEntityRegistry(client, { entities: [], stored: false }, [definition() as any], 'admin');
    expect(client.index.mock.calls[0][0]).toMatchObject({ id: CUSTOM_ENTITIES_DOC_ID, op_type: 'create' });
    await saveCustomEntityRegistry(client, saved, [definition() as any], 'admin');
    expect(client.index.mock.calls[1][0]).toMatchObject({ if_seq_no: 4, if_primary_term: 1 });

    client.index.mockRejectedValueOnce({ meta: { statusCode: 409 } });
    await expect(saveCustomEntityRegistry(client, saved, [], 'admin')).rejects.toMatchObject({ statusCode: 409 });
    await expect(saveCustomEntityRegistry(client, saved, [definition({ id: 'Bad' }) as any], 'admin')).rejects.toMatchObject({ statusCode: 400 });
  });

  test('finds which non-deleted rules use each custom entity, including retired aliases', async () => {
    const rule = (name: string, entity: string, extra: any = {}) => ({
      _id: name,
      _source: {
        name,
        trigger: { entityExpression: { version: 1, groups: [{ id: 'g', order: 0, predicates: [{ id: 'p', order: 0, entity, operator: 'exists' }] }] } },
        ...extra,
      },
    });
    expect(customEntityIdsInRule(rule('a', 'win_target_user')._source)).toEqual(['win_target_user']);
    const client = { search: jest.fn().mockResolvedValue({ body: { hits: { hits: [
      rule('AUTH-01', 'win_target_user'),
      rule('NET-01', 'custom:logon_ip'),
      rule('OLD', 'custom:logon_ip', { deleted_at: '2026-01-01T00:00:00Z' }),
      rule('BUILTIN', 'srcip'),
    ] } } }) };
    expect(await customEntityUsage(client)).toEqual({ win_target_user: ['AUTH-01'], logon_ip: ['NET-01'] });
  });
});
