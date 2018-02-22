# checkconn — simple connection checker

A simple tool to check whether TCP connections can be established.

Pass it one or more destinations (in `host:port` form, or HTTP(S) URLs) and it
will attempt to connect to each, printing a report of one line per host. There
is a built-in 2-second timeout, and it will attempt to establish multiple
connections in parallel in order to print a quick response even if given a
number of hosts that do not respond.

Hosts may be specified as:
 - hostnames
 - IPv4 addresses
 - IPv6 addresses (written as `[addr]`)

Ports may be specifed as:
 - port numbers
 - port names (from `/etc/services`)

It also understands `http://` and `https://` prefixed destinations, and it
will perform a simple HTTP GET to the given URI.

## TODO list

It would be very good to have some summary of TLS-enabled destinations.
