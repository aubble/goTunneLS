# goTunneLS

## Description

TLS wrapper in go! Wrap existing connections in TLS to bypass annoying DPI (deep packet filtering) from blocking your ssh connection or just protect insecure connections.

## Install

	go get -u github.com/aubble/goTunneLS

Make sure your $GOPATH/bin is in your $PATH. Now you should be able to launch it with just

	goTunneLS

Use the -c flag to point it to a config file, the default location it looks for is /etc/goTunneLS/config.json if no flag is provided.

####[Configuration](#configuration-1)
Learn how to configure the program. Please also read the included config.json and the Example section. They provide a hands on example to understand the configuration and usage of the program.

####[Configuring Certificates and Keys](#configuring-certificates-and-keys)
If you want to understand how certificates work and how to generate your own certificates to use.

####[Example](#example)
An easy to follow example to understand how the program works. Works along side the included config.json file.

**If you're a newbie, read all of the documentation I've wrote specifically for you to get you to understand!**

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

The configuration file's syntax is JSON and it consists of an array of the nodes structs each with the following fields, and then the path to the logFile. A neat simple example file, config.json, is included.

	{
		"Nodes": [
			{
				"Name": "nc -l",
				"Mode": "server",
				"Accept": "5001",
				"Connect": "5000",
				"Cert": "tls/cert.pem",
				"Key": "tls/key.pem"
			},
			{
				"Name": "nc",
				"Mode": "client",
				"Accept": "5002",
				"Connect": "5001",
				"Cert": "tls/cert.pem"
			}
		],
		"LogPath": "/dev/stdout"
	}

Note: read [example](#example) for a little tutorial on using it and the rest of the program.

First is the Nodes array which consists of structs that represent the nodes to launch followed by LogPath to point to the logging file. The following section explains all the fields allowed in the structs representing nodes as well as an explanation of LogPath.

###Fields

You can use relative file paths, relative to the config file. eg say the config file is in /etc/goTunneLS. If the value of the Cert field is "cert.pem" that really means "/etc/goTunneLS/cert.pem"

When it says int just put a integer such as 10 for the value, otherwise the value is implied as a string.

Don't bother with the optional fields if you don't care, they aren't necessary. Most people likely only want to use the required fields.

####Required

Mode -- sets node as client/server

Name -- name for logging

Accept -- listen address; format is host:port. If host is missing, localhost is assumed

Connect -- dial address; format is host:port. If host is missing, localhost is assumed


####Optional

Timeout -- int -- duration to sleep in seconds after network errors, default is 15

TCPKeepAliveInterval -- int -- interval between TCP keep alives in seconds, default is 15


####Required Server Fields

Cert -- path to the certificate that the server presents to clients

Key -- path to the key file of the Cert


####Optional Server fields

Issuer -- path to the issuer file of the cert. Only used in OCSP to validate the response from the OCSP responder.

OCSPInterval -- int --interval between OCSP staple updates in seconds. Only applies when the OCSP responder has the most up to date information, otherwise the interval between OCSP staple updates will be until the next update. Default is 180.

SessionKeyRotationInterval -- int -- interval between session key rotation in seconds, default is 28800 or 8 hours.


####Optional Client Options

Cert -- path to the RootCA for the certificate from the server. Useful when using self signed certificates (like below) that are not in the operating systems store, you must use this option to point to the RootCA in those cases or you'll get a nasty error about the certificate not being trusted.


####LogPath
It's the path to logFile. Created if doesn't exist, and if deleted during execution also recreated. Use /dev/stdout or /dev/stderr to output to terminal when needed.

The format for logging is:

	goTunneLS: year/month/date hour/minute/second --> mode name -/ message

When its global logging the mode is global and name is empty

For example

	goTunneLS: 2015/09/03 07:04:42 --> global -/ starting client node nc
	goTunneLS: 2015/09/03 07:04:42 --> client nc -/ initializing


##Configuring Certificates and Keys
TLS works with certificates and asymmetric cryptography. Lets first understand what that means. Skip this section if you already know how it all works and just want to get to generating the cert/key.

####Certificates?
This is a very vast topic and this is a very dumbed down version, but sufficient enough for you to be able to use this program.

#####Symmetric Cryptography
This is the type of cryptography you already understand. Symmetric cryptography both parties must know the same key to decrypt/encrypt. However this is a problem on the web, you can't send the key over to the client to initiate a encrypted session. If someone is listening and they grab the key, your entire session can be very easily decrypted. This is where asymmetric cryptography comes into play.

#####Asymmetric Cryptography
Asymmetric cryptography is based on the premise of special maths and algorithms that allow you to generate two keys with a special property. Anything decrypted with one key, can only be decrypted by the other key as well as vice versa. Why is this crucial?

This means that you can send out one key (the public key, or certificate) to other people to encrypt some data. They encrypt this data and send it back over to you, and you are the only one who can decrypt it because you are the only one who has the private key. Doesn't matter who's listening, they only get the public key, the key used to encrypt, not the key used to decrypt, and therefore they cannot decrypt.

The other advantage of asymmetric cryptography is signing. eg If something is encrypted via the private key, it can only be decrypted via the public key correct? This means that whenever something is successfully decrypted via the public key you are 100% sure that the it comes from whoever has the private key, as no one else can encrypt data to be decrypted with the public key.

#####Trust
Signing comes into play with trust. If I setup a fake server with a certificate with the name www.google.com, it shouldn't be trusted to be legit. It should be rejected as insecure. But how, how will my computer know the difference between the legit certificate from google and the fake one?

Well your computer comes with a set of root CAs (certificate authorities), basically a bunch of certificates that your computer 100% trusts as legit. These certificates are used to sign other certificates to validate their authenticity. eg they use their private key to sign certificates so that you can successfully decrypt certificates with the CAs public key, thus validating the certificate. (the root CAs are self signed, therefore you just have to trust them as being legit, trust has to begin somewhere)

The root CAs private keys are very securely protected so that certificates are only signed to the actual domain owners and not random people. You can create your own CA, add it to your computers store, and then sign a bunch of certificates to use privately. But remember that these certificates will only be trusted by computers who trust the CA you created.

In the example section we do this, the certificate used is actually a CA certificate. As long as this CA cert is in the clients trust store, the certificate is trusted. This is why the Client node accepts the Cert field. The Cert field for the client is what points it to the CA you want to use to validate the certificate from the server. Since the certificate we use on server is self signed, its CA is itself.

Don't worry about the actual math behind it, I myself have a very primitive understanding. If you understand the above, you're good enough to use this program. If you don't, please take the time to research it a bit, it'll go a long way.

###Generating Certificates

I've already setup a openssl.cnf that should setup the correct openssl options for most people, this should make it much more streamlined for beginners. Just cd into the tls folder to where it is located before running any commands.

Open openssl.cnf and modify the req\_distinguished\_name to fit your liking. Change the domain name (common name), email etc.

In order to use the certificate with multiple domain names, uncomment subjectAltName, [ alt\_names ], DNS.1 and DNS.2 and replace COMMON.NAME with the domain name set in req\_distinguished\_name and replace SECOND.NAME with the second name you want to use. You can also add more names with DNS.n where n is the next number.

You can also use wildcards in domain names to match all sub domains. eg you can set the common name to "\*.example.com" to match all of example.com's subdomains such as www.example.com, but it won't match example.com, you'll need to set a second DNS name for that.

Next choose whether or not you want to use ECDSA or RSA as the algorithm behind your certificate. I'd recommend ECDSA because the key sizes are smaller, its faster, and more secure. But if for some reason you want RSA, it works perfectly fine.

####ECDSA - RECOMMENDED
Creating a ECDSA signed cert is a two step process.
First generate the key with

	openssl ecparam -genkey -name secp384r1 -out key.pem

If you want a different curve to be used on the key, first list out the curves with

	openssl ecparam -list_curves

Select whatever you want and replace the -name portion with the curve name you want. For example if I wanted to use the prime256v1 curve which is less secure but quicker

	openssl ecparam -genkey -name prime256v1 -out key.pem

Next create the cert

	openssl req -new -x509 -config openssl.cnf -key key.pem -nodes -out cert.pem

There you go, you're done :)

####RSA
You can edit the default\_bits field in the openssl.cnf if you don't want a RSA key size of 4096 but maybe instead 2048.

Once you are ready cd into the tls directory and run

	openssl req -new -x509 -config openssl.cnf -nodes -out cert.pem

That command will generate a self signed certificate and key for you in the directory to use with goTunneLS. Make sure you changed the CN in openssl.cnf to match the domain name of your server and you're good to go!

##Example
Lets take a look at the example configuration file, config.json to get an idea of how goTunneLS is configured and how it works.
First start a goTunneLS instance with the -c flag pointing to the configuration file

	goTunneLS -c config.json

Leave that open and open a new terminal. Now run

	nc -l 5000

This opens up the nc application listening and accepting connections on port 5000. It then outputs whatever is received on these connections to stdout, which in this case is connected to your terminal.

Leave that nc running and open a new terminal. Now run

	nc localhost 5002

This makes nc dial port 5002 on localhost. Now when you type anything into the nc terminal, and press enter it appears on the other nc instance running in the other terminal! but wait.... the port numbers are different how could this be, how are they connected??? Thats goTunneLS doing its magic.

In that configuration file there are two goTunneLS "nodes" defined, 1 server and 1 client. The client's Listen address is port 5002 and Connect is to port 5001. This means it accepts plain TCP connections on port 5002 and proxies them to port 5001 with TLS TCP. The Server's listen address is port 5001, and Connect address is port 5000. This means it accepts TLS TCP connections on port 5001 and proxies them to port 5000 with plain TCP.

The entire ordeal looks as follow.

<pre>
              port 5002              port 5001              port 5000
+----------+      +---------------+      +---------------+      +----------+
|          |      |               +######+               |      |          |
|    nc    +------+  gTLS client  |------|  gTLS server  +------+   nc -l  |
|          |      |               +######+               |      |          |
+----------+      +---------------+      +---------------+      +----------+
</pre>

Hopefully it makes more sense now to you. nc does everything over plain text and goTunneLS allows you to wrap its insecure connection in TLS. You can take out the server node of the config.json, and take it and actually run it on a server somewhere, just change the Connect address of the client node to the new servers listening address and everything will work the same. Quite fun right? :P

Read the log messages from goTunneLS, you can see what its doing, the tunnels its creating, the certificates its loading, errors etc. I've used /dev/stdout as the logPath in config.json to output to standard output but you can make it a file in the current directory by setting it to "logs". Try it!

Note: The client and server are configured with a default self signed certificate I've provided. When actually using this program for real purposes, please look at the [Configuring Certificates and Keys](#configuring-certificates-and-keys) section to generate a new key pair. Anyone who has this key.pem file can decrypt your communications (the configuring certificates section also includes a small introduction, please read it if you do not know what I mean).

##ITS ALIVE!
<img src="http://i.imgur.com/1s2v4l6.png">


## Contribute

Contributions are very welcome. File issues for bugs, fix bugs with a pull request and if you think there is a very essential feature missing from goTunneLS, feel free to either submit a pull request or open a issue.

## Contact

Feel free to contact me at anmol@aubble.com

Feel free to edit the code, its not complicated and very well documented. Start at main.go and branch from there and you'll understand exactly how everything works very quickly. Also skip the OCSP code if it doesn't matter to you, its not very important or integral to the concept of the program. Its just for more secure TLS configurations.
