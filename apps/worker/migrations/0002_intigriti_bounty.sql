-- 0002: bounty range (Intigriti minBounty/maxBounty) + tier của asset
-- ticket #4

ALTER TABLE programs ADD COLUMN IF NOT EXISTS min_bounty NUMERIC(14, 2);
ALTER TABLE programs ADD COLUMN IF NOT EXISTS max_bounty NUMERIC(14, 2);
ALTER TABLE assets  ADD COLUMN IF NOT EXISTS tier TEXT;

CREATE INDEX IF NOT EXISTS idx_programs_max_bounty ON programs(max_bounty);
