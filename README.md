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

to generate a good certificate + private key run and use keypair.pem as a path in the X509Paths array for server.
You can add it as a path in the array for the client as well or you can add it to your OS's trusted certs for client.

sudo openssl req -new -x509 -newkey 4096 -sha256 -nodes -out keypair.pem -keyout keypair.pem

or save following as openssl.cnf

[ req ]
default_bits           = 4096
default_keyfile        = keyfile.pem
default_md             = sha256
default_keyfile        = keypair.pem
distinguished_name     = req_distinguished_name
prompt                 = no
x509_extensions        = v3_ca
encrypt_key            = no

[ req_distinguished_name ]
C                      = CA
ST                     = Ontario
L                      = Mississauga
O                      = aubble
CN                     = *.aubble.com
emailAddress           = info@aubble.com

[ v3_ca]
subjectAltName 		   = @alt_names

[alt_names]
DNS.1 				   = *.aubble.com
DNS.2 				   = aubble.com


and run command
sudo openssl req -new -x509 -days 365 -config openssl.cnf -out keypair.pem


#TODO ECDSA and algorithm fix certificate