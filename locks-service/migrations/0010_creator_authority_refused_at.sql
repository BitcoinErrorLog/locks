-- Time of the last real revalidation that the creator's homeserver refused.
-- NULL while the authority is usable; a successful check or a new approval clears it.
ALTER TABLE creator_authorities ADD COLUMN refused_at TIMESTAMPTZ;
