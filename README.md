#Dnsdb

Keep a database in sync with dns.

Gets dns notify messages, and uses zone transfers (AXFR or IXFR)
to keep a database in sync with the zone.

Can handle zones with the same name coming from different servers,
or zones from the same server signed with different TSIG keys (but
you'll need to configure your server with the various keys to use.)

Can't (yet?) handle keys with the same name from different servers,
but in principle there's no reason why not.
