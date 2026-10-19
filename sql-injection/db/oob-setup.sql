-- OOB SQLi capability — deliberately-weak condition for the out-of-band scenario.
--
-- Registers the loadable `oob_dns` UDF (compiled into the plugin dir by the db
-- image) so SQL can make the database emit a DNS query to the attacker's
-- collector, with a stolen value folded into the queried hostname.
-- Loaded by db.startup as root, after the seed import.
--
-- A loadable UDF is global, so the application account `portal` can call it with
-- no extra grant — which is why a single injected SELECT through /search is
-- enough to trigger the leak.
DROP FUNCTION IF EXISTS oob_dns;
CREATE FUNCTION oob_dns RETURNS STRING SONAME 'oob_dns.so';
