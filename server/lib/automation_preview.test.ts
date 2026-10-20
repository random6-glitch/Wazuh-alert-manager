import { CorrelationRule } from '../../common';
import { planAutomation } from './automation_planner';
import { simulateAutomationPreview } from './automation_preview';
// [CUSTOM ENTITIES] used to build alerts exactly as sync stores them.
import { projectOperationalAlert } from './operational_projection';
import { DEFAULT_CUSTOM_ENTITIES } from './custom_entities';

const now = new Date('2026-08-28T12:00:00.000Z');
const rule = (patch: any = {}): CorrelationRule => ({
  id: 'candidate',
  name: 'candidate',
  enabled: false,
  revision: 3,
  match: { ruleIds: ['100'] },
  trigger: { type: 'burst', entity: 'agent', threshold: 3, windowMinutes: 5 },
  actions: { createCase: true, caseSeverity: 'high', setStatus: 'closed', assignTo: 'robot' },
  preconditions: { statuses: ['open'], assignment: 'unassigned' },
  safety: { acknowledgeMatchAll: false },
  ...patch,
} as CorrelationRule);
const alert = (id: string, minute: number, source: any = {}) => ({
  id,
  source: {
    '@timestamp': `2026-08-28T11:${String(minute).padStart(2, '0')}:00.000Z`,
    status: 'open',
    assigned_to: null,
    agent: { name: 'host-a' },
    rule: { id: '100', groups: ['auth'], level: 8 },
    ...source,
  },
});

describe('exact automation preview', () => {
  test('uses a sliding burst window rather than the whole lookback and reports missing entities', () => {
    const result = simulateAutomationPreview(
      rule(),
      [alert('a', 40), alert('b', 50), alert('c', 55), alert('missing', 56, { agent: {} })],
      [],
      new Set(),
      { now, lookbackHours: 1 }
    );
    expect(result.triggeringEntities).toEqual([]);
    expect(result.casesCreated).toBe(0);
    expect(result.missingEntities).toBe(1);
  });

  test('matches planner conflict, order, precondition, and stop behavior exactly', () => {
    const candidate = rule({ trigger: { type: 'per_alert' }, actions: { createCase: false, setStatus: 'closed' }, priority: 20 });
    const winner = rule({ id: 'winner', enabled: true, trigger: { type: 'per_alert' }, actions: { createCase: false, setStatus: 'in_progress' }, priority: 10 });
    const alerts = [alert('z', 59)];
    const expected = planAutomation(alerts, [{ ...winner, enabled: true }, { ...candidate, enabled: true }]);
    const result = simulateAutomationPreview(candidate, alerts, [winner], new Set(), { now, lookbackHours: 1 });
    expect(result.conflicts).toEqual(expected[0].conflicts.map((conflict) => ({ alertId: 'z', ...conflict })));
    expect(result.statusChanges).toBe(0);
  });

  test('applies action/case caps and existing-case dedup without writes', () => {
    const candidate = rule({ safety: { acknowledgeMatchAll: false, maxActionsPerRun: 1, maxCasesPerRun: 1 } });
    const alerts = [alert('a', 55), alert('b', 56), alert('c', 57), alert('d', 58, { agent: { name: 'host-b' } }), alert('e', 59, { agent: { name: 'host-b' } }), alert('f', 59, { agent: { name: 'host-b' } })];
    const result = simulateAutomationPreview(candidate, alerts, [], new Set(['candidate|host-a']), { now, lookbackHours: 1 });
    expect(result.casesExtended).toBe(1);
    expect(result.casesCreated).toBe(1);
    expect(result.statusChanges + result.assignments).toBe(1);
  });

  test('has activation and durable rate-limit parity with live event-time evaluation', () => {
    const candidate = rule({
      trigger: { type: 'per_alert' }, actions: { createCase: false, setStatus: 'closed' },
      safety: { acknowledgeMatchAll: false, rateLimit: { maxExecutions: 1, windowMinutes: 60 } },
    });
    const first = alert('first', 58, { ingested_at: '2026-08-28T11:58:30.000Z' });
    const second = alert('second', 59, { ingested_at: '2026-08-28T11:59:30.000Z' });
    const result = simulateAutomationPreview(candidate, [first, second], [], new Set(), {
      now, lookbackHours: 1, effectiveFrom: '2026-08-28T11:59:00.000Z',
      rateLimitReservations: { candidate: [{ id: 'existing', timestamp: '2026-08-28T11:30:00.000Z' }] },
    });
    expect(result.matchingAlerts).toBe(1);
    expect(result.statusChanges).toBe(0);
    expect(result.rateLimited).toBe(true);
  });

  // [CUSTOM ENTITIES] Reproduces AUTH-01: rule 60122 (Windows 4625) alerts carry
  // the account only in data.win.eventdata.targetUserName.
  test('Windows logon failures correlate on custom:win_target_user but not on dstuser', () => {
    const raw = (id: string, minute: number, user: string) => projectOperationalAlert({
      _index: 'wazuh-alerts-4.x-2026.08.28', _id: id,
      _source: {
        '@timestamp': `2026-08-28T11:${String(minute).padStart(2, '0')}:00.000Z`,
        agent: { name: 'win-host' },
        rule: { id: '60122', level: 5, groups: ['windows', 'authentication_failed'] },
        data: { win: { eventdata: { targetUserName: user }, system: { eventID: '4625' } } },
      },
    }, '2026-08-28T11:00:00.000Z', DEFAULT_CUSTOM_ENTITIES);
    const alerts = [raw('a', 50, 'Administrator'), raw('b', 51, 'administrator'), raw('c', 52, 'ADMINISTRATOR'), raw('d', 53, '-')]
      .map((source) => ({ id: source.alert_uid, source }));
    const authRule = (entity: string) => rule({
      match: { ruleIds: ['60122'] },
      trigger: {
        type: 'burst', threshold: 3, windowMinutes: 10,
        entityExpression: { version: 1, groups: [{ id: 'g', order: 0, predicates: [{ id: 'p', order: 0, entity, operator: 'exists' }] }] },
      },
    });

    const before = simulateAutomationPreview(authRule('dstuser'), alerts, [], new Set(), { now, lookbackHours: 1 });
    expect(before.matchingAlerts).toBe(4);
    expect(before.missingEntities).toBe(4);
    expect(before.casesCreated).toBe(0);

    for (const entity of ['custom:win_target_user', 'win_target_user']) {
      const after = simulateAutomationPreview(authRule(entity), alerts, [], new Set(), { now, lookbackHours: 1 });
      expect(after.matchingAlerts).toBe(4);
      expect(after.missingEntities).toBe(1); // the "-" placeholder is ignored
      expect(after.casesCreated).toBe(1);
    }
  });
});
