-- UP: Seed data — entity-type whitelist and the EAV attribute registry.
-- INSERT-only (no DDL) so soma-schema classifies this as a SEED migration.
-- Idempotent: re-running upserts by natural key. `id` defaults to
-- gen_random_uuid() and timestamps default to now(), so only business columns
-- are listed (no sentinel UUIDs).

-- Entity types: secret and config_key are the two first-class vault entities.
INSERT INTO "01_vault"."01_dim_entity_types" (code, name, description)
VALUES
    ('secret',     'Secret',     'A versioned encrypted secret value.'),
    ('config_key', 'Config Key', 'A typed configuration key with versioned values.')
ON CONFLICT (code) DO UPDATE SET
    name        = EXCLUDED.name,
    description = EXCLUDED.description,
    updated_at  = now();

-- Attribute registry: the default EAV attributes for each entity type.
-- All is_required=false for MVP; is_pii=false (none carry PII directly).
-- sort_order controls UI display order (lower = earlier). Add a field here =
-- a new seed row, never a schema migration.
INSERT INTO "01_vault"."02_dim_attr_defs" (entity_type, code, name, data_type, is_required, is_pii, sort_order)
VALUES
    ('secret', 'description',            'Description',              'text', false, false, 1),
    ('secret', 'tags',                   'Tags',                     'text', false, false, 2),
    ('secret', 'owner_team',             'Owner Team',               'text', false, false, 3),
    ('secret', 'rotation_interval_days', 'Rotation Interval (Days)', 'int',  false, false, 4),
    ('secret', 'last_rotated_at',        'Last Rotated At',          'text', false, false, 5),
    ('secret', 'notes',                  'Notes',                    'text', false, false, 6),
    ('config_key', 'description',     'Description',  'text', false, false, 1),
    ('config_key', 'owner_team',      'Owner Team',   'text', false, false, 2),
    ('config_key', 'is_feature_flag', 'Feature Flag', 'bool', false, false, 3),
    ('config_key', 'notes',           'Notes',        'text', false, false, 4)
ON CONFLICT (entity_type, code) DO UPDATE SET
    name        = EXCLUDED.name,
    data_type   = EXCLUDED.data_type,
    is_required = EXCLUDED.is_required,
    is_pii      = EXCLUDED.is_pii,
    sort_order  = EXCLUDED.sort_order,
    updated_at  = now();

-- DOWN ==
DELETE FROM "01_vault"."02_dim_attr_defs"
WHERE (entity_type, code) IN (
    ('secret',     'description'),
    ('secret',     'tags'),
    ('secret',     'owner_team'),
    ('secret',     'rotation_interval_days'),
    ('secret',     'last_rotated_at'),
    ('secret',     'notes'),
    ('config_key', 'description'),
    ('config_key', 'owner_team'),
    ('config_key', 'is_feature_flag'),
    ('config_key', 'notes')
);

DELETE FROM "01_vault"."01_dim_entity_types"
WHERE code IN ('secret', 'config_key');
