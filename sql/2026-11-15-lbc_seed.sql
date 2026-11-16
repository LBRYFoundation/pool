-- Recent additions to add after db init (.gz)
-- mysql yaamp -p < file.sql

-- LBRY pool seed data. Safe to re-run.

-- The 2016 dump has no row for the lbry algo (stratum default algo, web YAAMP_DEFAULT_ALGO)
INSERT INTO algos (name, profit, rent, factor, overflow)
SELECT 'lbry', 0, 0, 1, 0 FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM algos WHERE name = 'lbry');
