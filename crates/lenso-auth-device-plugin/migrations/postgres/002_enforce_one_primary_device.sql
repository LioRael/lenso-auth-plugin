DO $migration$
BEGIN
    IF EXISTS (
        SELECT subject_id
        FROM auth_devices
        WHERE primary_at IS NOT NULL
        GROUP BY subject_id
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION 'cannot enforce one primary device while duplicate primary rows exist';
    END IF;
END
$migration$;

CREATE UNIQUE INDEX auth_devices_one_primary_per_subject_idx
    ON auth_devices(subject_id)
    WHERE primary_at IS NOT NULL;
