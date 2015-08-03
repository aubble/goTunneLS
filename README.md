# goTunneLS
TLS wrapper in go.

***ACTIVLEY BEING DEVELOPED CARE***

It allows you to wrap insecure connections in TLS.
Run a client goTunneLS instance that listens on a port for
incoming connections and then tunnels these connections to a
server goTunneLS instance (doesn't need to be goTunneLS,
as no special protocol is used, client only connects and pushes data,
could be server stunnel for all it cares) which is configured to tunnel to the final destination.
Configure the settings in tunnels.json.

Name is the name for logging.

Connect is the address to tunnel data to after receiving a connection on the accept address.

Accept is the address to listen on for connections, and then tunnel over to the connect address.

Mode defines the direction of the tunnel, server listens for TLS connections to unwrap and tunnel
to connect address, client listens for plain connections to wrap and tunnel to connect address.

Certs is an array of paths for PEM formatted x509 certificates with server mode and
in client mode the root certificates.

Timeout is how long to wait after a network error before trying again.

Feel free to edit the code, its fairly easy and well documented.
