# goTunneLS

***ACTIVLEY BEING DEVELOPED BE VARY***

## Description
TLS wrapper in go! Wrap existing connections in TLS to bypass annoying DPI, and protect your connections.

Feel free to edit the code, its fairly easy and very well documented.

to generate a good certificate + private key run and use keypair.pem as a path in the X509Paths array for server.
You can add it as a path in the array for the client as well or you can add it to your OS's trusted certs for client.

sudo openssl req -new -x509 -newkey 4096 -sha256 -nodes -out cert.pem -keyout key.pem

or save following as openssl.cnf (edit as u see fit)

[ req ]
default_bits           = 4096
default_keyfile        = key.pem
default_md             = sha256
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

and run command: openssl req -new -x509 -days 365 config openssl.cnf -out cert.pem

for ecdsa key run: sudo openssl ecparam -genkey -name secp384r1 -out key.pem
then just add -key key.pem to the first command and remove -newkey 4096, for config file just add -key key.pem.

//TODO ECDSA and algorithm fix certificate
