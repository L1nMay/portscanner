ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS targets_count INTEGER;

ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS ports_spec TEXT;

ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS notes TEXT;

-- заполняем данные из старых колонок (если были)
UPDATE scans
SET
    ports_spec = ports
WHERE ports_spec IS NULL;

UPDATE scans
SET
    notes = status
WHERE notes IS NULL;
