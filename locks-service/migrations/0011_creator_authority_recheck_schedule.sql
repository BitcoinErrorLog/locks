-- When the next recheck may run, and how many checks in a row failed to produce
-- an honored answer. NULL next_check_at means the row has no schedule yet and
-- is due from its last honored or refused timestamp.
--
-- An image that does not embed this migration will not start after it is applied.
ALTER TABLE creator_authorities
    ADD COLUMN next_check_at TIMESTAMPTZ,
    ADD COLUMN check_failure_count INTEGER NOT NULL DEFAULT 0;
