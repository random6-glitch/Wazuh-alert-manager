/**
 * [CUSTOM ENTITIES] Registry and backfill API.
 *
 *   GET    /custom-entities              registry + which rules use each entry (any user; the rule editor needs it)
 *   POST   /custom-entities              add an entry                     (admin)
 *   PUT    /custom-entities/{id}         edit an entry                    (admin)
 *   DELETE /custom-entities/{id}         remove an unused entry           (admin)
 *   POST   /custom-entities/backfill     re-compute last N hours          (admin)
 *
 * Changing fieldPath or valueType, or deleting, is refused while any rule
 * uses the entry: either change would silently alter correlation/case keys of
 * rules already running. Label, description and ignore values stay editable.
 */
import { schema } from '@osd/config-schema';
import { IRouter } from '../../../../src/core/server';
import {
  API_ROOT,
  CustomEntityDefinition,
  CUSTOM_ENTITY_ID_PATTERN,
  CUSTOM_ENTITY_VALUE_TYPES,
  MAX_CUSTOM_ENTITY_BACKFILL_HOURS,
} from '../../common';
import { requirePluginAdmin } from '../lib/authorization';
import {
  customEntityUsage,
  loadCustomEntityRegistry,
  saveCustomEntityRegistry,
  validateCustomEntityDefinition,
} from '../lib/custom_entities';
import { backfillCustomEntities } from '../lib/custom_entity_backfill';

const valueTypeSchema = schema.oneOf(CUSTOM_ENTITY_VALUE_TYPES.map((value) => schema.literal(value)) as any);
const editableFields = {
  label: schema.string({ minLength: 1, maxLength: 80 }),
  fieldPath: schema.string({ minLength: 1, maxLength: 700 }),
  valueType: valueTypeSchema,
  ignoreValues: schema.arrayOf(schema.string({ maxLength: 256 }), { maxSize: 20, defaultValue: [] }),
  description: schema.maybe(schema.string({ maxLength: 500 })),
};
const idParam = schema.object({
  id: schema.string({ validate: (value) => (new RegExp(CUSTOM_ENTITY_ID_PATTERN).test(value) ? undefined : 'Invalid custom entity ID.') }),
});

function fail(response: any, error: any) {
  return response.customError({
    statusCode: error?.statusCode || error?.meta?.statusCode || 500,
    body: { message: error?.message || 'Request failed.', ...(error?.errors ? { attributes: { errors: error.errors } } : {}) },
  });
}

async function actorName(context: any, request: any): Promise<string> {
  return (await requirePluginAdmin(context, request)).name;
}

export function defineCustomEntityRoutes(router: IRouter) {
  router.get({ path: `${API_ROOT}/custom-entities`, validate: false }, async (context, request, response) => {
    try {
      const client = context.core.opensearch.client.asCurrentUser;
      const [registry, usage] = await Promise.all([loadCustomEntityRegistry(client), customEntityUsage(client)]);
      return response.ok({ body: { entities: registry.entities, usage } });
    } catch (error: any) {
      return fail(response, error);
    }
  });

  router.post(
    { path: `${API_ROOT}/custom-entities`, validate: { body: schema.object({ id: schema.string({ maxLength: 40 }), ...editableFields }) } },
    async (context, request, response) => {
      try {
        const actor = await actorName(context, request);
        const client = context.core.opensearch.client.asCurrentUser;
        const state = await loadCustomEntityRegistry(client);
        const input = request.body as any;
        const errors = validateCustomEntityDefinition(input);
        if (errors.length) return response.badRequest({ body: { message: errors[0], attributes: { errors } } });
        if (state.entities.some((entity) => entity.id === input.id)) {
          return response.customError({ statusCode: 409, body: { message: `Custom entity "${input.id}" already exists.` } });
        }
        const now = new Date().toISOString();
        const created: CustomEntityDefinition = { ...input, created_at: now, created_by: actor, updated_at: now, updated_by: actor };
        const saved = await saveCustomEntityRegistry(client, state, [...state.entities, created], actor);
        return response.ok({ body: { entities: saved.entities } });
      } catch (error: any) {
        return fail(response, error);
      }
    }
  );

  router.put(
    { path: `${API_ROOT}/custom-entities/{id}`, validate: { params: idParam, body: schema.object(editableFields) } },
    async (context, request, response) => {
      try {
        const actor = await actorName(context, request);
        const client = context.core.opensearch.client.asCurrentUser;
        const { id } = request.params as any;
        const [state, usage] = await Promise.all([loadCustomEntityRegistry(client), customEntityUsage(client)]);
        const current = state.entities.find((entity) => entity.id === id);
        if (!current) return response.notFound({ body: { message: `Custom entity "${id}" does not exist.` } });
        const input = request.body as any;
        const rewired = input.fieldPath.trim() !== current.fieldPath || input.valueType !== current.valueType;
        if (rewired && usage[id]?.length) {
          return response.customError({
            statusCode: 409,
            body: {
              message: `Field path and value type cannot change while rules use "${id}" (${usage[id].join(', ')}). ` +
                'Create a new custom entity and move the rules to it instead.',
            },
          });
        }
        const next: CustomEntityDefinition = { ...current, ...input, id, updated_at: new Date().toISOString(), updated_by: actor };
        const errors = validateCustomEntityDefinition(next);
        if (errors.length) return response.badRequest({ body: { message: errors[0], attributes: { errors } } });
        const saved = await saveCustomEntityRegistry(
          client, state, state.entities.map((entity) => (entity.id === id ? next : entity)), actor
        );
        return response.ok({ body: { entities: saved.entities } });
      } catch (error: any) {
        return fail(response, error);
      }
    }
  );

  router.delete(
    { path: `${API_ROOT}/custom-entities/{id}`, validate: { params: idParam } },
    async (context, request, response) => {
      try {
        const actor = await actorName(context, request);
        const client = context.core.opensearch.client.asCurrentUser;
        const { id } = request.params as any;
        const [state, usage] = await Promise.all([loadCustomEntityRegistry(client), customEntityUsage(client)]);
        if (!state.entities.some((entity) => entity.id === id)) {
          return response.notFound({ body: { message: `Custom entity "${id}" does not exist.` } });
        }
        if (usage[id]?.length) {
          return response.customError({
            statusCode: 409,
            body: { message: `"${id}" is used by: ${usage[id].join(', ')}. Remove it from those rules first.` },
          });
        }
        const saved = await saveCustomEntityRegistry(client, state, state.entities.filter((entity) => entity.id !== id), actor);
        return response.ok({ body: { entities: saved.entities } });
      } catch (error: any) {
        return fail(response, error);
      }
    }
  );

  router.post(
    {
      path: `${API_ROOT}/custom-entities/backfill`,
      validate: { body: schema.object({ hours: schema.number({ min: 1, max: MAX_CUSTOM_ENTITY_BACKFILL_HOURS }) }) },
    },
    async (context, request, response) => {
      try {
        await requirePluginAdmin(context, request);
        const client = context.core.opensearch.client.asCurrentUser;
        const { entities } = await loadCustomEntityRegistry(client);
        const result = await backfillCustomEntities(client, entities, { hours: (request.body as any).hours });
        return response.ok({ body: result });
      } catch (error: any) {
        return fail(response, error);
      }
    }
  );
}
