/**
 * [CUSTOM ENTITIES] Settings > Correlation entities.
 *
 * Admins register a raw Wazuh field (dot path) as a correlation entity. Once
 * saved it appears in the rule editor's Entity dropdown as its label, and is
 * stored on rules as "custom:<id>". The backfill panel re-computes values for
 * alerts already synced, so previews over recent history work immediately.
 */
import React, { useCallback, useEffect, useState } from 'react';
import {
  EuiBadge,
  EuiBasicTable,
  EuiButton,
  EuiButtonEmpty,
  EuiButtonIcon,
  EuiCallOut,
  EuiCode,
  EuiComboBox,
  EuiConfirmModal,
  EuiDescriptionList,
  EuiFieldNumber,
  EuiFieldText,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFlyout,
  EuiFlyoutBody,
  EuiFlyoutFooter,
  EuiFlyoutHeader,
  EuiFormRow,
  EuiPanel,
  EuiSelect,
  EuiSpacer,
  EuiText,
  EuiTextArea,
  EuiTitle,
  EuiToolTip,
} from '@elastic/eui';
import {
  CustomEntityBackfillResult,
  CustomEntityDefinition,
  CustomEntityValueType,
  CUSTOM_ENTITY_ID_PATTERN,
  CUSTOM_ENTITY_PATH_PATTERN,
  CUSTOM_ENTITY_PREFIX,
  MAX_CUSTOM_ENTITIES,
  MAX_CUSTOM_ENTITY_BACKFILL_HOURS,
} from '../../common';
import { AlertsApiService } from '../services/api';

interface Props {
  apiService: AlertsApiService;
  onToast: (title: string, color: 'success' | 'danger' | 'primary', text?: string) => void;
}

export const VALUE_TYPE_LABEL: Record<CustomEntityValueType, string> = {
  text_ci: 'Text (case-insensitive)',
  text: 'Text (exact)',
  ip: 'IP address',
  port: 'Port',
};
const VALUE_TYPE_OPTIONS = (Object.keys(VALUE_TYPE_LABEL) as CustomEntityValueType[]).map((value) => ({
  value,
  text: VALUE_TYPE_LABEL[value],
}));
const ID_RE = new RegExp(CUSTOM_ENTITY_ID_PATTERN);
const PATH_RE = new RegExp(CUSTOM_ENTITY_PATH_PATTERN);

type Draft = Omit<CustomEntityDefinition, 'created_at' | 'created_by' | 'updated_at' | 'updated_by'>;
const emptyDraft = (): Draft => ({ id: '', label: '', fieldPath: '', valueType: 'text_ci', ignoreValues: [], description: '' });

/** Suggest an id from a field path: data.win.eventdata.ipAddress -> ip_address */
const suggestId = (path: string) => {
  const last = path.split('.').pop() || '';
  const slug = last.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase().replace(/[^a-z0-9_]/g, '_').replace(/^[^a-z]+/, '');
  return slug.slice(0, 40);
};

const errorMessage = (error: any) =>
  error?.body?.attributes?.errors?.join(' ') || error?.body?.message || error?.message || 'Request failed.';

export const CustomEntitiesView: React.FC<Props> = ({ apiService, onToast }) => {
  const [entities, setEntities] = useState<CustomEntityDefinition[]>([]);
  const [usage, setUsage] = useState<Record<string, string[]>>({});
  const [isAdmin, setIsAdmin] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<CustomEntityDefinition | null>(null);
  const [backfillHours, setBackfillHours] = useState(24);
  const [backfilling, setBackfilling] = useState(false);
  const [backfillResult, setBackfillResult] = useState<CustomEntityBackfillResult | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const [registry, capabilities] = await Promise.all([
        apiService.fetchCustomEntities(),
        apiService.fetchSystemCapabilities().catch(() => ({})),
      ]);
      setEntities(registry.entities || []);
      setUsage(registry.usage || {});
      setIsAdmin(Boolean((capabilities as any)?.isPluginAdmin));
    } catch (error: any) {
      setLoadError(errorMessage(error));
    } finally {
      setLoading(false);
    }
  }, [apiService]);

  useEffect(() => {
    load();
  }, [load]);

  const inUse = (id: string) => (usage[id] || []).length > 0;
  const lockedFields = !!editingId && inUse(editingId);

  const draftErrors = (value: Draft): string[] => {
    const errors: string[] = [];
    if (!editingId) {
      if (!ID_RE.test(value.id)) errors.push('ID: start with a letter; lower-case letters, digits and _ only (max 40).');
      else if (entities.some((entity) => entity.id === value.id)) errors.push(`ID "${value.id}" already exists.`);
    }
    if (!value.label.trim()) errors.push('Label is required.');
    if (!PATH_RE.test(value.fieldPath.trim())) errors.push('Field path must be a dot path such as data.win.eventdata.ipAddress.');
    return errors;
  };

  const openAdd = () => {
    setEditingId(null);
    setDraft(emptyDraft());
  };
  const openEdit = (entity: CustomEntityDefinition) => {
    setEditingId(entity.id);
    setDraft({ ...emptyDraft(), ...entity, description: entity.description || '' });
  };

  const save = async () => {
    if (!draft) return;
    const errors = draftErrors(draft);
    if (errors.length) {
      onToast('Fix the highlighted fields', 'danger', errors.join(' '));
      return;
    }
    setSaving(true);
    const body = {
      label: draft.label.trim(),
      fieldPath: draft.fieldPath.trim(),
      valueType: draft.valueType,
      ignoreValues: draft.ignoreValues,
      ...(draft.description?.trim() ? { description: draft.description.trim() } : {}),
    };
    try {
      if (editingId) await apiService.updateCustomEntity(editingId, body);
      else await apiService.createCustomEntity({ id: draft.id, ...body });
      onToast(editingId ? 'Custom entity updated' : 'Custom entity added', 'success',
        editingId ? undefined : 'Run a backfill below so alerts already synced get this field.');
      setDraft(null);
      await load();
    } catch (error: any) {
      onToast('Could not save custom entity', 'danger', errorMessage(error));
    } finally {
      setSaving(false);
    }
  };

  const doDelete = async () => {
    if (!confirmDelete) return;
    try {
      await apiService.deleteCustomEntity(confirmDelete.id);
      onToast('Custom entity removed', 'success');
      setConfirmDelete(null);
      await load();
    } catch (error: any) {
      setConfirmDelete(null);
      onToast('Could not remove custom entity', 'danger', errorMessage(error));
    }
  };

  const runBackfill = async () => {
    setBackfilling(true);
    setBackfillResult(null);
    try {
      const result = await apiService.backfillCustomEntities(backfillHours);
      setBackfillResult(result);
      onToast('Backfill finished', result.failed ? 'danger' : 'success', `${result.updated.toLocaleString()} alerts updated.`);
    } catch (error: any) {
      onToast('Backfill failed', 'danger', errorMessage(error));
    } finally {
      setBackfilling(false);
    }
  };

  const columns: any[] = [
    {
      field: 'label',
      name: 'Entity',
      render: (label: string, entity: CustomEntityDefinition) => (
        <div>
          <strong>{label}</strong>
          <EuiText size="xs" color="subdued"><EuiCode>{`${CUSTOM_ENTITY_PREFIX}${entity.id}`}</EuiCode></EuiText>
        </div>
      ),
    },
    { field: 'fieldPath', name: 'Source field', render: (path: string) => <EuiCode>{path}</EuiCode> },
    { field: 'valueType', name: 'Value type', render: (type: CustomEntityValueType) => VALUE_TYPE_LABEL[type] || type },
    {
      field: 'ignoreValues',
      name: 'Ignored values',
      render: (values: string[]) => (values?.length ? values.map((value) => <EuiBadge key={value} color="hollow">{value}</EuiBadge>) : '—'),
    },
    {
      field: 'id',
      name: 'Used by',
      render: (id: string) => {
        const rules = usage[id] || [];
        if (!rules.length) return <EuiText size="s" color="subdued">No rules</EuiText>;
        return (
          <EuiToolTip content={rules.join(', ')}>
            <EuiBadge color="primary">{rules.length === 1 ? '1 rule' : `${rules.length} rules`}</EuiBadge>
          </EuiToolTip>
        );
      },
    },
    ...(isAdmin
      ? [{
          name: 'Actions',
          width: '90px',
          render: (entity: CustomEntityDefinition) => (
            <EuiFlexGroup gutterSize="xs" responsive={false}>
              <EuiFlexItem grow={false}>
                <EuiButtonIcon iconType="pencil" aria-label={`Edit ${entity.label}`} onClick={() => openEdit(entity)} />
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiToolTip content={inUse(entity.id) ? 'Remove it from the rules that use it first.' : 'Remove'}>
                  <EuiButtonIcon
                    iconType="trash"
                    color="danger"
                    aria-label={`Remove ${entity.label}`}
                    isDisabled={inUse(entity.id)}
                    onClick={() => setConfirmDelete(entity)}
                  />
                </EuiToolTip>
              </EuiFlexItem>
            </EuiFlexGroup>
          ),
        }]
      : []),
  ];

  return (
    <>
      <EuiPanel paddingSize="l">
        <EuiFlexGroup alignItems="center" justifyContent="spaceBetween" responsive={false}>
          <EuiFlexItem>
            <EuiTitle size="s"><h3>Correlation entities</h3></EuiTitle>
            <EuiText size="s" color="subdued">
              <p>
                Register any field from your Wazuh alerts as a correlation entity. Registered entities appear in
                the Entity dropdown of every automation rule&apos;s trigger, next to the built-in ones.
              </p>
            </EuiText>
          </EuiFlexItem>
          {isAdmin && (
            <EuiFlexItem grow={false}>
              <EuiButton
                fill
                iconType="plusInCircle"
                onClick={openAdd}
                isDisabled={entities.length >= MAX_CUSTOM_ENTITIES}
              >
                Add custom field
              </EuiButton>
            </EuiFlexItem>
          )}
        </EuiFlexGroup>
        <EuiSpacer size="m" />
        {!isAdmin && !loading && (
          <>
            <EuiCallOut size="s" iconType="lock" title="Read only: administrator permission is required to change correlation entities." />
            <EuiSpacer size="m" />
          </>
        )}
        {loadError && (
          <>
            <EuiCallOut color="danger" iconType="alert" title="Correlation entities could not be loaded">
              <p>{loadError}</p>
            </EuiCallOut>
            <EuiSpacer size="m" />
          </>
        )}
        <EuiBasicTable
          items={entities}
          itemId="id"
          loading={loading}
          columns={columns}
          noItemsMessage={loading ? 'Loading…' : 'No custom entities yet. Use "Add custom field" to register one.'}
        />
      </EuiPanel>

      <EuiSpacer size="l" />

      <EuiPanel paddingSize="l">
        <EuiTitle size="s"><h3>Backfill recent alerts</h3></EuiTitle>
        <EuiText size="s" color="subdued">
          <p>
            Custom entities are copied while alerts sync, so alerts synced before an entity was added or changed do
            not have it yet. Backfill re-reads only the registered fields from the original Wazuh alerts and updates
            the alert copies. Status, case and assignment are not touched.
          </p>
        </EuiText>
        <EuiSpacer size="m" />
        <EuiFlexGroup alignItems="flexEnd" responsive={false}>
          <EuiFlexItem grow={false} style={{ width: 180 }}>
            <EuiFormRow label="Last N hours">
              <EuiFieldNumber
                min={1}
                max={MAX_CUSTOM_ENTITY_BACKFILL_HOURS}
                value={backfillHours}
                onChange={(event) => setBackfillHours(Math.max(1, Math.min(MAX_CUSTOM_ENTITY_BACKFILL_HOURS, Number(event.target.value) || 1)))}
                disabled={!isAdmin || backfilling}
              />
            </EuiFormRow>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiButton iconType="refresh" onClick={runBackfill} isLoading={backfilling} isDisabled={!isAdmin || !entities.length}>
              Backfill
            </EuiButton>
          </EuiFlexItem>
        </EuiFlexGroup>
        {backfillResult && (
          <>
            <EuiSpacer size="m" />
            <EuiCallOut
              size="s"
              color={backfillResult.failed ? 'warning' : 'success'}
              iconType={backfillResult.failed ? 'alert' : 'check'}
              title={`Backfill of the last ${backfillResult.hours} hours finished`}
            >
              <EuiDescriptionList
                type="column"
                compressed
                listItems={[
                  { title: 'Alerts scanned', description: backfillResult.scanned.toLocaleString() },
                  { title: 'Updated', description: backfillResult.updated.toLocaleString() },
                  { title: 'Original alert unavailable', description: backfillResult.missingSource.toLocaleString() },
                  { title: 'Failed', description: backfillResult.failed.toLocaleString() },
                ]}
              />
              {backfillResult.truncated && (
                <p>The alert limit was reached; the newest alerts were processed first. Use a shorter window to cover the rest.</p>
              )}
            </EuiCallOut>
          </>
        )}
      </EuiPanel>

      {draft && (
        <EuiFlyout size="s" onClose={() => setDraft(null)} ownFocus aria-labelledby="customEntityFlyoutTitle">
          <EuiFlyoutHeader hasBorder>
            <EuiTitle size="s">
              <h2 id="customEntityFlyoutTitle">{editingId ? 'Edit custom field' : 'Add custom field'}</h2>
            </EuiTitle>
          </EuiFlyoutHeader>
          <EuiFlyoutBody>
            {lockedFields && (
              <>
                <EuiCallOut size="s" iconType="lock" title="Source field and value type are locked">
                  <p>
                    Used by {usage[editingId!].join(', ')}. Changing them would change those rules&apos; case keys.
                    Add a new custom field instead and move the rules to it.
                  </p>
                </EuiCallOut>
                <EuiSpacer size="m" />
              </>
            )}
            <EuiFormRow
              label="Source field path"
              helpText="Dot path inside the Wazuh alert, as shown in Discover. Example: data.win.eventdata.ipAddress"
            >
              <EuiFieldText
                value={draft.fieldPath}
                placeholder="data.win.eventdata.targetUserName"
                disabled={lockedFields}
                onChange={(event) => {
                  const fieldPath = event.target.value;
                  const autoId = !editingId && (!draft.id || draft.id === suggestId(draft.fieldPath));
                  setDraft({ ...draft, fieldPath, ...(autoId ? { id: suggestId(fieldPath) } : {}) });
                }}
              />
            </EuiFormRow>
            <EuiFormRow label="Label" helpText="Shown in the rule editor's Entity dropdown.">
              <EuiFieldText value={draft.label} placeholder="Windows logon source IP" onChange={(event) => setDraft({ ...draft, label: event.target.value })} />
            </EuiFormRow>
            <EuiFormRow
              label="ID"
              helpText={editingId ? 'IDs cannot change after creation.' : `Rules store this as ${CUSTOM_ENTITY_PREFIX}${draft.id || '<id>'}. Lower-case letters, digits and _.`}
            >
              <EuiFieldText value={draft.id} disabled={!!editingId} onChange={(event) => setDraft({ ...draft, id: event.target.value.trim() })} />
            </EuiFormRow>
            <EuiFormRow label="Value type" helpText="Controls how values are compared and grouped.">
              <EuiSelect
                options={VALUE_TYPE_OPTIONS}
                value={draft.valueType}
                disabled={lockedFields}
                onChange={(event) => setDraft({ ...draft, valueType: event.target.value as CustomEntityValueType })}
              />
            </EuiFormRow>
            <EuiFormRow label="Ignored values" helpText="Placeholders treated as missing, e.g. - or 127.0.0.1. Type a value and press Enter.">
              <EuiComboBox
                noSuggestions
                selectedOptions={draft.ignoreValues.map((value) => ({ label: value }))}
                onCreateOption={(value) => {
                  const trimmed = value.trim();
                  if (trimmed && !draft.ignoreValues.includes(trimmed)) setDraft({ ...draft, ignoreValues: [...draft.ignoreValues, trimmed] });
                }}
                onChange={(options) => setDraft({ ...draft, ignoreValues: options.map((option) => option.label) })}
              />
            </EuiFormRow>
            <EuiFormRow label="Description (optional)">
              <EuiTextArea rows={2} value={draft.description || ''} onChange={(event) => setDraft({ ...draft, description: event.target.value })} />
            </EuiFormRow>
            {draftErrors(draft).length > 0 && (draft.fieldPath || draft.label) && (
              <>
                <EuiSpacer size="s" />
                <EuiCallOut size="s" color="warning" title={draftErrors(draft)[0]} />
              </>
            )}
          </EuiFlyoutBody>
          <EuiFlyoutFooter>
            <EuiFlexGroup justifyContent="spaceBetween" responsive={false}>
              <EuiFlexItem grow={false}>
                <EuiButtonEmpty onClick={() => setDraft(null)}>Cancel</EuiButtonEmpty>
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiButton fill onClick={save} isLoading={saving} isDisabled={draftErrors(draft).length > 0}>
                  {editingId ? 'Save changes' : 'Add field'}
                </EuiButton>
              </EuiFlexItem>
            </EuiFlexGroup>
          </EuiFlyoutFooter>
        </EuiFlyout>
      )}

      {confirmDelete && (
        <EuiConfirmModal
          title={`Remove "${confirmDelete.label}"?`}
          onCancel={() => setConfirmDelete(null)}
          onConfirm={doDelete}
          cancelButtonText="Cancel"
          confirmButtonText="Remove"
          buttonColor="danger"
        >
          <p>It will disappear from the Entity dropdown. New alerts stop carrying its value.</p>
        </EuiConfirmModal>
      )}
    </>
  );
};
