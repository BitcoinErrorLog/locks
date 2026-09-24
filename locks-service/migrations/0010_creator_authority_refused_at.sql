-- Time of the last real revalidation that the creator's homeserver refused.
-- NULL while the authority is usable; a successful check or a new approval clears it.
--
-- Rolling the image back past this migration is not supported: an image that embeds
-- only 0001-0009 refuses to start (sqlx reports VersionMissing(10)). Recovery is a
-- fix-forward image that keeps this migration.
ALTER TABLE creator_authorities ADD COLUMN refused_at TIMESTAMPTZ;
