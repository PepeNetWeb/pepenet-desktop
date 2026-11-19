-- Example read-only queries against an indexer db.
--   sqlite3 'file:pep.db?mode=ro' < examples/queries.sql

-- sync tip
SELECT MAX(height) AS tip FROM blocks;

-- owner of one name (hash160 hex)
SELECT name, lower(hex(owner)) AS owner, st, lease_expiry FROM names WHERE name = 'gm';

-- names held by one hash160
SELECT name, lease_expiry, st FROM names
 WHERE owner = x'2222222222222222222222222222222222222222' ORDER BY name;

-- names listed for sale
SELECT name, price, offer_expiry FROM names WHERE price > 0 ORDER BY price;

-- leases expiring soonest
SELECT name, lease_expiry FROM names WHERE owner IS NOT NULL ORDER BY lease_expiry LIMIT 20;

-- name count per owner
SELECT lower(hex(owner)) AS owner, COUNT(*) AS n FROM names
 WHERE owner IS NOT NULL GROUP BY owner ORDER BY n DESC LIMIT 20;
