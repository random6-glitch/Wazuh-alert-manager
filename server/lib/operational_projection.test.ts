import { alertUid, legacyAlertUid, projectOperationalAlert } from './operational_projection';

describe('operational alert projection', () => {
  test('uses source index and id for stable collision-safe identity', () => {
    expect(alertUid('wazuh-alerts-a', 'same')).toBe(alertUid('wazuh-alerts-a', 'same'));
    expect(alertUid('wazuh-alerts-a', 'same')).not.toBe(alertUid('wazuh-alerts-b', 'same'));
    expect(legacyAlertUid('same')).not.toBe(alertUid('wazuh-alerts-a', 'same'));
  });

  test('allowlists operational fields and drops arbitrary source data', () => {
    const doc = projectOperationalAlert({
      _index: 'wazuh-alerts-4.x-2026.08.28',
      _id: 'abc',
      _source: {
        '@timestamp': '2026-08-28T00:00:00.000Z',
        agent: { id: '001', name: 'host', ip: '10.0.0.2' },
        rule: { id: '5502', level: 5, groups: 'syslog', description: 'test' },
        data: {
          srcip: '10.0.0.1', srcport: '443', dstport: 65535,
          password: 'must-not-copy', process: '/bin/sh',
        },
        secret: 'must-not-copy',
      },
    });
    expect(doc.data.srcip).toBe('10.0.0.1');
    expect(doc.data.process.name).toBe('/bin/sh');
    expect(doc.data.srcport).toBe(443);
    expect(doc.data.dstport).toBe(65535);
    expect(doc.data.password).toBeUndefined();
    expect(doc.secret).toBeUndefined();
    expect(doc.source_index).toBe('wazuh-alerts-4.x-2026.08.28');
  });

  // [CUSTOM ENTITIES] Registry paths are copied, normalized, into custom_entities; nothing else from data.win.
  test('projects registry fields into custom_entities only', () => {
    const registry = [
      { id: 'win_target_user', label: 'u', fieldPath: 'data.win.eventdata.targetUserName', valueType: 'text_ci' as const, ignoreValues: ['-'] },
      { id: 'logon_ip', label: 'ip', fieldPath: 'data.win.eventdata.ipAddress', valueType: 'ip' as const, ignoreValues: [] },
      { id: 'absent', label: 'a', fieldPath: 'data.nothing.here', valueType: 'text' as const, ignoreValues: [] },
    ];
    const hit = {
      _index: 'wazuh-alerts-a', _id: 'w1',
      _source: { data: { win: {
        eventdata: { targetUserName: 'Administrator', logonType: '3', ipAddress: '010.0.0.5' },
        system: { eventID: '4625' },
      } } },
    };
    const doc = projectOperationalAlert(hit, undefined, registry);
    expect(doc.custom_entities).toEqual({ win_target_user: ['administrator'], logon_ip: ['10.0.0.5'] });
    expect(doc.data.win).toBeUndefined();
    // An unreadable registry (null) omits the field so a sync upsert keeps existing values.
    expect(projectOperationalAlert(hit, undefined, null)).not.toHaveProperty('custom_entities');
    expect(projectOperationalAlert(hit)).not.toHaveProperty('custom_entities');
  });

  test('drops invalid port values rather than indexing malformed integers', () => {
    const doc = projectOperationalAlert({
      _index: 'wazuh-alerts-a', _id: '1',
      _source: { data: { srcport: 'not-a-port', dstport: 70000 } },
    });
    expect(doc.data.srcport).toBeNull();
    expect(doc.data.dstport).toBeNull();
  });
});
