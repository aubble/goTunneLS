# goTunneLS

***ACTIVLEY BEING DEVELOPED BE VARY***


## Description

TLS wrapper in go! Wrap existing connections in TLS to bypass annoying DPI (deep packet filtering) if you're say using SSH and being blocked, or to just protect your connections.

## Install

	go get -u github.com/aubble/goTunneLS

## How it works

 * +++ represents plain data 
 
 * \#\#\# represents TLS encrypted data

### Normal connections

**client &nbsp; ---> &nbsp; server**

The link between the client and server is either insecure or it uses say SSH as the protocol which is picked up by DPI and thus blocked. You can tunnel it instead through a goTunneLS tunnel which is encrypted via TLS, which makes it much less likely to be blocked by DPI as the entire web uses TLS.

### goTunneLS connections

**client &nbsp; +++---> &nbsp; gTLS client &nbsp; ###--> &nbsp; gTLS server &nbsp; +++---> &nbsp; server**

Now the difference is that whatever the client sends to the gTLS client is forwarded over to the gTLS server and then finally over to the server and vice-versa. The advantage here is that the gTLS client and gTLS server communicate via TLS thus protecting the data if the client/server communicate insecurely and also likely bypassing any DPI as TLS is almost never blocked.

#### gTLS Client

Basically the client listens on a address for plain TCP connections and proxies them to another address via TLS and TCP.

#### gTLS Server

Basically the server does the exact opposite. It listens on a address for TLS TCP connections and then proxies those over to another address via plain TCP.

## Instructions

The configuration file's syntax is JSON and it consists of an array of the nodes structs each with the following fields, and the path to the logFile. Each of these nodes in the array are either in server or client mode depending on the Mode field. Please take a look at the example config.json for an example

###Options

**Mode -- required always**
Sets node as client/server

Name
Name for logging

#####Accept -- required
Listen address; format is host:port. If host is missing, localhost is assumed

#####Connect -- required
Dial address; format is host:port. If host is missing, localhost is assumed

#####Timeout
Duration to sleep in seconds after network errors

#####TCPKeepAliveInterval 
Interval between TCP keep alives


####Server Options

#####Cert -- required
Path to the certificate file to send to client

#####Key -- required
Path to the key file 

#####Issuer
Path to the issuer file of the cert. Only used in OCSP to validate the response.

#####OCSPInterval
Interval between OCSP staple updates in seconds. Only applies when the OCSP responder has the most up to date information, otherwise the interval between OCSP staple updates will be until the next update.

#####SessionKeyRotationInterval 
Interval between session key rotation in seconds


####Client Options

#####Cert
Optional field in a client node for the path of the RootCA for the certificate from the server.
Useful when using self signed certificates.

####LogPath
Path to the log file


## Example
Lets take a look at the example configuration file to get an idea of how its configured.
It not only shows off every option in both the client and server configurations, but it's also a neat little exercise. First run a goTunneLS instance with the -c flag pointing to the configuration file (the default location it looks for is /etc/goTunneLS/config.json)

	goTunneLS -c config.json

then run

	nc -l 5000

this opens up the nc application listening and accepting connections on port 5000. It then outputs whatever is recieved on these connections to stdout, which in this case is connected to your terminal.

leave that nc running and open a new terminal side by side. now run

	nc localhost 5002

this makes nc dial port 5002 on localhost (the same computer its running on). you'll notice that now when you type anything, and press enter it appears on the other nc instance running in the other terminal! but wait.... the port numbers are different how could this be? Thats goTunneLS doing its magic.

In that configuration file there are two goTunneLS "nodes" defined, 1 server and 1 client. The client listens on port 5002 and proxies to port 5001 which is where the server is listening. The server then proxies the data to port 5000 which is where nc -l is listening.

Hopefully it makes more sense now to you. nc does everything over plain text and goTunneLS allows you to wrap its insecure connection in TLS. You can take out the server node of the config.json, and take it and actually run it on a server somewhere, just change the Connect address of the client node to the Server's listening address and everything will work the same. You just tunneled nc through TLS!

Now that you understand how it works, also know that its pure TLS, know that no other protocol is being used other than TLS to tunnel so its not necessary to use both the server and client. If a application communicates via TLS but the other does not, you only need to wrap insecure one.

## Contribute

Contributions are very welcome. File issues for bugs, fix bugs with a pull request and if you think there is a very essential feature missing from goTunneLS, feel free to either submit a pull request or open a issue.

## Contact 

Feel free to contact me at anmol@aubble.com

Feel free to edit the code, its not complicated and very well documented. Start at main.go and branch from there and you'll understand exactly how everything works very quickly. Also skip the OCSP code if it doesn't matter to you, its not every important or integral to the concept. Its just for more secure TLS configurations.
