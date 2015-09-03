# goTunneLS

## Description

TLS wrapper in go! Wrap existing connections in TLS to bypass annoying DPI (deep packet filtering) from blocking your ssh connection or just protect insecure connections.

## Install

	go get -u github.com/aubble/goTunneLS

Make sure your $GOPATH/bin is in your $PATH. Now you should be able to launch it with just

	goTunneLS

Use the -c flag to point it to a config file, the default location it looks for is /etc/goTunneLS/config.json if no -c flag is provided.

## How it works

 * --- represents plain data

 * \#\#\# represents the TLS tunnel around the plain data

### Normal connections
<pre>
+----------+                                                    +----------+
|          |                                                    |          |
|  client  +----------------------------------------------------+  server  |
|          |                                                    |          |
+----------+                                                    +----------+
</pre>

The link between the client and server is either insecure or it uses say SSH as the protocol which is picked up by Deep Packet Filtering and thus blocked. You can tunnel it instead through a goTunneLS tunnel which is encrypted via TLS, which makes it much less likely to be blocked by DPI as the entire web uses TLS, its far too restrictive for most networks and you should be able to get through!

### goTunneLS connections
<pre>
+----------+      +---------------+      +---------------+      +----------+
|          |      |               +######+               |      |          |
|  client  +------+  gTLS client  |------|  gTLS server  +------+  server  |
|          |      |               +######+               |      |          |
+----------+      +---------------+      +---------------+      +----------+
</pre>

Now the difference is that whatever the client sends to the gTLS client is forwarded over to the gTLS server and then finally over to the real server. The advantage here is that the gTLS client and gTLS server communicate via TLS thus protecting the data if the client/server communicate insecurely and also likely bypassing any DPI as TLS is almost never blocked.

#### gTLS Client

Basically the client listens on it's Accept address for plain TCP connections and proxies them to its Connect address via TLS and TCP.

#### gTLS Server

Basically the server does the exact opposite. Listens on it's Accept address for TLS TCP connections and proxies them to its Connect address via plain TCP.

---

Now that you understand how it works, also know that its pure TLS, know that no other protocol is being used other than TLS to tunnel so its not necessary to use both the server and client. If a application communicates via TLS but the other does not, you only need to wrap insecure one.


## Configuration

The configuration file's syntax is JSON and it consists of an array of the nodes structs each with the following fields, and then the path to the logFile. A neat simple example file, config.json, is included. Please read it, its very simple. Read [example](#example) for a little tutorial on using it and the rest of the program.

Anyways, each of these nodes in the array are either in server or client mode depending on the Mode field. Otherwise here is the list of fields you can set in all the nodes.

Note that you can use relative file paths, relative to the config file. So say the config file is in /etc/goTunneLS. If the value of Cert is "cert.pem" that really means "/etc/goTunneLS/cert.pem" as its relative to the config file. The moment goTunneLS gets the name of the config file as the argument it changes its directory to it.

###Fields

####Required

Mode -- sets node as client/server

Name -- name for logging

Accept -- listen address; format is host:port. If host is missing, localhost is assumed

Connect -- dial address; format is host:port. If host is missing, localhost is assumed


####Optional

Timeout -- duration to sleep in seconds after network errors, default is 15

TCPKeepAliveInterval -- interval between TCP keep alives in seconds, default is 15


####Required Server Fields

Cert -- path to the certificate that the server presents to clients

Key -- path to the key file of the Cert


####Optional Server fields

Issuer -- path to the issuer file of the cert. Only used in OCSP to validate the response.

OCSPInterval -- interval between OCSP staple updates in seconds. Only applies when the OCSP responder has the most up to date information, otherwise the interval between OCSP staple updates will be until the next update. Default is 180

SessionKeyRotationInterval -- interval between session key rotation in seconds, default is 28800 or 8 hours


####Optional Client Options

Cert -- path to the RootCA for the certificate from the server. Useful when using self signed certificates (like below) that are not in the operating systems store, you must use this option to point to the RootCA in those cases or you'll get a nasty error.


###LogPath
Outside of the array of nodes this is the other variable. It's the path to logFile. Created if doesn't exist, and if deleted during execution also recreated. Use /dev/stdout or /dev/stderr to output to terminal when needed.

##Configuring certificates and keys
TLS works with certificates and asymmetric cryptography. Lets first understand what that means. Skip this section if you already know how it all works and just want to get to generating the cert/key.

####Certificates?? Keys?? What does it all mean??


---

I've already setup a openssl.cnf that should setup the correct openssl options for most people, you can of course use any certificate you want but this should make it much more streamlined for beginners.

Open tls/openssl.cnf and modify the req\_distinguished\_name to fit your liking. Change the name and everything. Next choose if you want RSA or ECDSA. I recommend going for ECDSA, the keys are shorter and faster and more secure.

####ECDSA - RECOMMENDED
Creating a ECDSA signed cert is a two step process.
First generate the key with

	openssl ecparam -genkey -name secp384r1 -out key.pem

If you want a different curve to be used on the key, first list out the curves with

	openssl ecparam -list_curves

select it and replace the -name portion with the curve name you want. for example if I wanted to use the prime256v1 curve

	openssl ecparam -genkey -name prime256v1 -out key.pem

Next create the cert

	openssl req -new -x509 -config openssl.cnf -key key.pem -nodes -out cert.pem

There you go, you're done :)

####RSA
You can edit the default\_bits field in the openssl.cnf if you don't want a RSA key size of 4096 but maybe instead 2048.

Once you are ready cd into the tls directory and run

	openssl req -new -x509 -config openssl.cnf -nodes -out cert.pem

That command will generate a self signed certificate and key for you in the directory to use with goTunneLS. Make sure you changed the CN in openssl.cnf to match the domain name of your server and you're good to go!

---

Now whenever you set the client config, make sure Cert points to this generated certificate and when setting up the server config make sure Cert and Key point to their respective generated files here.

If you also want to use this cert with say the name localhost, example.com and www.example.com, open up openssl.cnf and uncomment subjectAltName, [ alt\_names ], DNS.1 and DNS.2 and replace COMMON.NAME with the common name (its called CN in openssl.cnf) and replace SECOND.NAME with the second name you want to use. You can also add more names with DNS.n where n is the next number. Thats it for the cert configuration!


## Example
Lets take a look at the example configuration file, config.json to get an idea of how goTunneLS is configured and how it works.
First start a goTunneLS instance with the -c flag pointing to the configuration file
//TODO DIAGRAM

	goTunneLS -c config.json

Leave that open and open a new terminal. Now run

	nc -l 5000

This opens up the nc application listening and accepting connections on port 5000. It then outputs whatever is received on these connections to stdout, which in this case is connected to your terminal.

Leave that nc running and open a new terminal. Now run

	nc localhost 5002

This makes nc dial port 5002 on localhost (the same computer its running on). You'll notice that now when you type anything, and press enter it appears on the other nc instance running in the other terminal! but wait.... the port numbers are different how could this be, how are they connected??? Thats goTunneLS doing its magic.

In that configuration file there are two goTunneLS "nodes" defined, 1 server and 1 client. The client's Listen address is port 5002 and Connect is to port 5001. This means it accepts plain TCP connections on port 5002 and proxies them to port 5001 with TLS TCP. The Server's listen address is port 5001, and Connect address is port 5000. This means it accepts TLS TCP connections on port 5001 and proxies them to port 5000 with plain TCP. The server is configured with a default certificate/key I've provided. Please look at the 

The entire ordeal looks as follow.

<pre>
			  port 5002     		 port 5001              port 5000
+----------+      +---------------+      +---------------+      +----------+
|          |      |               +######+               |      |          |
|    nc    +------+  gTLS client  |------|  gTLS server  +------+   nc -l  |
|          |      |               +######+               |      |          |
+----------+      +---------------+      +---------------+      +----------+
</pre>

Hopefully it makes more sense now to you. nc does everything over plain text and goTunneLS allows you to wrap its insecure connection in TLS. You can take out the server node of the config.json, and take it and actually run it on a server somewhere, just change the Connect address of the client node to the new servers listening address and everything will work the same. Quite fun right? :P

##ITS ALIVE!
<img src="http://i.imgur.com/1s2v4l6.png">


## Contribute

Contributions are very welcome. File issues for bugs, fix bugs with a pull request and if you think there is a very essential feature missing from goTunneLS, feel free to either submit a pull request or open a issue.

## Contact

Feel free to contact me at anmol@aubble.com

Feel free to edit the code, its not complicated and very well documented. Start at main.go and branch from there and you'll understand exactly how everything works very quickly. Also skip the OCSP code if it doesn't matter to you, its not very important or integral to the concept of the program. Its just for more secure TLS configurations.
