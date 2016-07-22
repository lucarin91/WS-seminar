# Authentication method in the web
### WS - Seminar

<small>Created by <a href="http://lucar.in">Luca Rinaldi</a></small>



# Agenda
- HTTP authentication framework

- session authentication system

- token authentication system

- token vs session

- conclusion



# HTTP Authentication Framework
Original standardization document **rfc2617** ("HTTP Authentication: Basic and Digest Access Authentication") from IETF(Internet Engineering Task Force) and than updated with:
- rfc7617 "The 'Basic' HTTP Authentication Scheme"
- rfc7616 "HTTP Digest Access Authentication"
- rfc6750 "The OAuth 2.0 Authorization Framework: Bearer Token Usage"


# Basic Authentication
A simple authentication system, in with the client send `user-id:password` encoded in Base64 in the `Authentication` header field

for example for user-id "Aladdin" and password "open sesame":
```
Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
```

note:
To receive authorization, the client:

1.  obtains the user-id and password from the user,

2.  constructs the user-pass by concatenating the user-id, a single
    colon (":") character, and the password,

3.  encodes the user-pass into an octet sequence (see below for a
    discussion of character encoding schemes),

4.  and obtains the basic-credentials by encoding this octet sequence
    using Base64 ([RFC4648], Section 4) into a sequence of US-ASCII
    characters ([RFC0020]).


## Digest Authentication
It's a challenge responce system, here the username and the password it's never trasmit in clear text.

The server send a random `nonce` and the client have to reply with `hash(user:password:nonce)`

note:
TO-ADD:
- two type session and non-session version
- the other required header keys


## Bearer Token
A security token with the property that any party in possession of
the token (a "bearer") can use the token in any way that any other
party in possession of it can.  Using a bearer token does not
require a bearer to prove possession of cryptographic key material
(proof-of-possession).

```
GET /resource HTTP/1.1
Host: server.example.com
Authorization: Bearer mF_9.B5f-4.1JqM
```



# From stateless to statefull
we want to avoid to communicate at every request username and password.

we need a way to authenticate a client throw a set of consecutively request.

note:
HTML is a stateless protocol, but usually application needs to keep information between two distinct calls.



# HTTP Web Session
with HTTP/1.1 and CGI there is the possibility to implement a statefull server

the we server can manage the session and retrieve it by a sessionID.

https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol#HTTP_session
https://en.wikipedia.org/wiki/Common_Gateway_Interface


## How thous work
![session-flow](img/session_flow.jpg)

note:
it use cookies to store sessionID on the client, than at each connection retrieve it from an hashtable inside the webserver.

http://machinesaredigging.com/2013/10/29/how-does-a-web-session-work/


## PHP example
```php
<?php
session_start();
if (!isset($_SESSION['count'])) {
  $_SESSION['count'] = 0;
} else {
  $_SESSION['count']++;
}
?>
```

note:
http://php.net/manual/en/reserved.variables.session.php


## Problem
http://technicalinfo.net/papers/WebBasedSessionManagement.html


## security issue



# Token


## JWT


## OAuth


## OpenID


## security issue



# Session vs Token



# Conclusion



# References
<div style="font-size: 24px;">
