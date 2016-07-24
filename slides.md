# Web Authentication Methods
### WS - Seminar

<small>Created by [Luca Rinaldi](http://lucar.in)</small>



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


# Basic HTTP Authentication *[rfc7617]*
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


## Digest HTTP Authentication *[rfc7616]*
It's a challenge responce system, the username and the password it is never transmit in clear text.

The server send a random `nonce` and the client have to reply with `hash(user:password:nonce)`

```
Authorization: Digest username="Mufasa",
                      realm="http-auth@example.org",
                      uri="/dir/index.html",
                      algorithm=MD5,
                      nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
                      nc=00000001,
                      cnonce="f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ",
                      qop=auth,
                      response="8ca523f5e9506fed4657c9700eebdbec",
                      opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"
```

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

we want to save same data for every single user

note:
HTML is a stateless protocol, but usually application needs to keep information between two distinct calls.



# HTTP Web Session
With HTTP/1.1 and CGI programming language and framework start to implement Web Session Manager.

They maintain session with the users and identified them with a **sessionID**.

note:
https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol#HTTP_session
https://en.wikipedia.org/wiki/Common_Gateway_Interface

is important that the sessionID is:
- highly random, to avoid prediction
- sufficient long, to avoid brute force attack (>= 50 character)


## How it work
<pre>
    +---------+                          +---------+              +---------+
    |         |  (A) POST /authenticate  |         |              |         |
    |         +-------------------------->         |     Create   |         |
    |         |  username=..&password=.. |         | (B) session  |         |
    |         |                          |         +-------------->         |
    |         |   (C) HTTP 200 OK        |         |              |         |
    |         <--------------------------+         |              |         |
    |         |  Set-cookie: session=..  |   Web   |              | Session |
    | Client  |                          |  Server |              | Manager |
    |         |                          |         |              |         |
    |         |                          |         |              |         |
    |         |   (D) HTTP GET           |         |              |         |
    |         +-------------------------->         |     Get user |         |
    |         |    Cookie: session=..    |         | (E) session  |         |
    |         |                          |         +-------------->         |
    |         |   (F) HTTP 200 OK        |         |              |         |
    |         <--------------------------+         |              |         |
    +---------+                          +---------+              +---------+
</pre>

<!--![session-flow](img/session_flow.jpg)-->

note:
it use cookies to store sessionID on the client, than at each connection retrieve it from an hash-table inside the web server.

http://machinesaredigging.com/2013/10/29/how-does-a-web-session-work/


## PHP example
```php
<?php
session_start();
if (!isset($_SESSION['user'])) {
    if ($_POST['username'] == 'luca' && $_POST['password'] == 'password'){
        $_SESSION['user'] = 'luca';
        $_SESSION['admin'] = true;
    }
} else {
  echo "username $_SESSION['user'] is logged ".
        ($_SESSION['admin'] ? "as admin" : "as user");
}
?>
```

note:
http://php.net/manual/en/reserved.variables.session.php



# Session/Cookies security issue
- Session Hijacking thought:
    - observation
    - brute force
    - XSS

- CSRF, because it rely on cookies

note:
CSRF: the site can be put in <iframe>, generate a POST request and re-use the existing authentication cookie to another request.
https://www.owasp.org/index.php/Session_hijacking_attack



# Tokens
It is an object contained the security credential to a login session

It can be of two type:
- self-contained token
- opaque token

note:
- self-contained token, These are tokens that conform to the JSON Web Token standard and contain information about an identity in the form of claims. They are self-contained in that it is not necessary for the recipient to call a server to validate the token.

- Opaque tokens, Opaque tokens are tokens in a proprietary format that typically contain some identifier to information in a server’s persistent storage. To validate an opaque token, the recipient of the token needs to call the server that issued the token.



# JSON Web Token *[rfc7519]*
It is a compact claims representation in JSON format.

It safeguard its integrity by:
- JSON Web Signature (JWS), a sign system.
- JSON Web Encryption (JWE), an encryption system.

note:
JSON Web Token (JWT) is a compact claims representation format intended for space constrained environments such as HTTP Authorization headers and URI query parameters. JWTs encode claims to be transmitted as a JSON [RFC7159] object that is used as the payload of a JSON Web Signature (JWS) [JWS] structure or as the plaintext of a JSON Web Encryption (JWE) [JWE] structure, enabling the claims to be digitally signed or integrity protected with a Message Authentication Code (MAC) and/or encrypted. JWTs are always represented using the JWS Compact Serialization or the JWE Compact Serialization.


## Claims
A piece of information asserted about a subject.

They can be:
- registered claims names (i.e. iss, exp, iat, jti..)
- public claims, the one in the IANA database
- private claims names, chosen by the users

note:
registered claims names:
    - iss: The issuer of the token
    - exp: Token expiration time defined in Unix time
    - iat: "Issued at" time, in Unix time, at which the token was issued
    - jti: JWT ID claim provides a unique identifier for the JWT


## Structure [1]
Header:
```json
{
    "alg": "HS256",
    "typ": "JWT"
}
```

Payload:
```json
{
    "iss": "lucar.in",
    "exp": 1469268709,
    "name": "luca",
    "admin": true,
}
```

Verify signature:
```javascript
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  "secret"
)
```


## Structure [2]
Generate the encoding version:
```javascript
base64UrlEncode(header) +
"." +
base64UrlEncode(payload) +
"." +
verify_signature
```

Encoded JWT:
```JSON
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
.
eyJpc3MiOiJsdWNhci5pbiIsImV4cCI6MTQ2OTI2ODcwOSwibmFtZSI6Imx1Y2EiLCJhZG1pbiI6dHJ1ZX0
.
5Z5tKUacfE-r_L56uaddeimgREpgk39Fbx6EJ3cuTJg
```


## Authentication Flow
<pre>
            +---------+                            +---------+
            |         |  (A) POST /authenticate    |         |
            |         +---------------------------->         +--------+
            |         |  username=..&password=..   |         |  (B)   |
            |         |                            |         |Generate|
            |         |   (C) HTTP 200 OK          |         |  JWT   |
            |         <----------------------------+         <--------+
            |         |      token: '..JWT..'      |         |
            |         |                            |   Web   |
            | Client  |                            |  Server |
            |         |                            |         |
            |         |   (D) HTTP GET             |         |
            |         +---------------------------->         +--------+
            |         | Authentication: Bearer JWT |         |  (E)   |
            |         |                            |         |Validate|
            |         |   (F) HTTP 200 OK          |         |  JWT   |
            |         <----------------------------+         <--------+
            +---------+                            +---------+
</pre>


## Insecure implementation
critical-vulnerabilities-in-json-web-token-libraries

note:
https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/



# OAuth 2.0 *[rfc6749]*
It enables a third-party application to obtain limited access to an HTTP service in behalf of a resource owner.

For example: </br>
*Draw.io, an online flow chart editor, that request the user to access their storage space on Dropbox, to save and load files.* <!-- .element: style="font-size: 26px"-->


## Roles
- resource owner, the end-user

- client, the third-part application

- resource server and authorization server, the service that manges the resource

note:
- resource owner, An entity capable of granting access to a protected resource. When the resource owner is a person, it is referred to as an end-user.

- resource server, The server hosting the protected resources, capable of accepting and responding to protected resource requests using access tokens.

- client, An application making protected resource requests on behalf of the resource owner and with its authorization.  The term "client" does not imply any particular implementation characteristics (e.g., whether the application executes on a server, a desktop, or other devices).

- authorization server, The server issuing access tokens to the client after successfully     authenticating the resource owner and obtaining authorization.


## General authentication flow
<pre>
            +--------+                               +---------------+
            |        |--(A)- Authorization Request ->|   Resource    |
            |        |                               |     Owner     |
            |        |<-(B)-- Authorization Grant ---|               |
            |        |                               +---------------+
            |        |
            |        |                               +---------------+
            |        |--(C)-- Authorization Grant -->| Authorization |
            | Client |                               |     Server    |
            |        |<-(D)----- Access Token -------|               |
            |        |                               +---------------+
            |        |
            |        |                               +---------------+
            |        |--(E)----- Access Token ------>|    Resource   |
            |        |                               |     Server    |
            |        |<-(F)--- Protected Resource ---|               |
            +--------+                               +---------------+
</pre>

note:
- (A) The client requests authorization from the resource owner. The authorization request can be made directly to the resource owner (as shown), or preferably indirectly via the authorization server as an intermediary.
- (B) The client receives an authorization grant, which is a credential representing the resource owner's authorization, expressed using one of four grant types defined in this specification or using an extension grant type. The authorization grant type depends on the method used by the client to request authorization and the types supported by the authorization server.
- (C) The client requests an access token by authenticating with the authorization server and presenting the authorization grant.
- (D) The authorization server authenticates the client and validates the authorization grant, and if valid, issues an access token.
- (E) The client requests the protected resource from the resource server and authenticates by presenting the access token.
- (F) The resource server validates the access token, and if valid, serves the request.


## Obtaining Authentication
- authorization code, optimized for **confidential clients**.

- implicit, optimized for **public clients**.

- resource owner password credentials, where the resource owner has a trust relationship with the client.

- client credentials, when the client is requesting access to the protected resources under its control.

note:
- authorization code, The authorization code grant type is used to obtain both access tokens and refresh tokens and is optimized for **confidential clients**.

- implicit, The implicit grant type is used to obtain access tokens (it does not support the issuance of refresh tokens) and is optimized for **public clients** known to operate a particular redirection URI.

- resource owner password credentials, The resource owner password credentials grant type is suitable in cases where the **resource owner has a trust relationship with the client**, such as the device operating system or a highly privileged application.

- client credentials, The client can request an access token using only its client credentials (or other supported means of authentication) when the client is requesting access to the protected resources under its control, or those of another resource owner that have been previously arranged with the authorization server (the method of which is beyond the scope of this specification).



# OpenID *[OpenID Connect 1.0]*
An identity layer on top of the OAuth 2.0 protocol.

It enables Clients to verify the identity of the End-User based on the authentication performed by an Authorization Server.

For example: </br>
*Flicker.com use as Authentication provider Yahoo to login an manager their users* <!-- .element: style="font-size: 26px"-->


## Connection Flow
<pre>
          +----------+                                   +----------+
          |          |                                   |          |
          |          |---------(A) AuthN Request-------->|          |
          |          |                                   |          |
          |          |  +--------+                       |          |
          |          |  |        |                       |          |
          |          |  |  End-  |<--(B) AuthN & AuthZ-->|          |
          |          |  |  User  |                       |          |
          |  Client  |  |        |                       |  OpenID  |
          |          |  +--------+                       | Provider |
          |          |                                   |          |
          |          |<--------(C) AuthN Response--------|          |
          |          |                                   |          |
          |          |---------(D) UserInfo Request----->|          |
          |          |                                   |          |
          |          |<--------(E) UserInfo Response-----|          |
          |          |                                   |          |
          +----------+                                   +----------+
</pre>

note:
- (A) The RP (Client) sends a request to the OpenID Provider (OP).
- (B) The OP authenticates the End-User and obtains authorization.
- (C) The OP responds with an ID Token and usually an Access Token.
- (D) The RP can send a request with the Access Token to the UserInfo Endpoint.
- (E) The UserInfo Endpoint returns Claims about the End-User.



# Token Security issue
- XSS, it's possible to steal saved token

- Invalidation system prone to error

- They can contain sensible information

note:
we can't use `HttpOnly` cookie flag


# Session vs Token Authentication
Token are:
- scalable
- efficient (memory and computational)
- CSRF immune
- Cross Domain and CORS (Cross-origin resource sharing)

Session are:
- centralized control
- XSS immune with `httpOnly` cookies
- less data send to each request



# Conclusion
If correctly implemented either the two system have the same security
strength.

One or the other dependence of the goal of the project, but the token implementation is more general and ready for mobile and modern web app application.



# References
<div style="font-size: 14px;">
- [RFC 7617 - **The 'Basic' HTTP Authentication Scheme** - IETF](https://tools.ietf.org/html/rfc7617). (2015, September). Retrieved July 23, 2016, from https://tools.ietf.org/html/rfc7617

- [RFC 7616 - **HTTP Digest Access Authentication** - IETF](https://tools.ietf.org/html/rfc7616). (2015, September). Retrieved July 23, 2016, from https://tools.ietf.org/html/rfc7616

- [RFC 6750 - **The OAuth 2.0 Authorization Framework: Bearer Token Usage** - IETF](https://tools.ietf.org/html/rfc6750). (2012, October). Retrieved July 23, 2016, from https://tools.ietf.org/html/rfc6750

- [**Web Based Session Management** - TechnicalInfo](http://technicalinfo.net/papers/WebBasedSessionManagement.html). (n.d.). Retrieved July 23, 2016, from http://technicalinfo.net/papers/WebBasedSessionManagement.html

- [**Session Management Cheat Sheet** - OWASP](https://www.owasp.org/index.php/Session_Management_Cheat_Sheet). (2016, June 1). Retrieved July 23, 2016, from https://www.owasp.org/index.php/Session_Management_Cheat_Sheet

- [**Session hijacking attack** - OWASP](https://www.owasp.org/index.php/Session_hijacking_attack). (2014, August 14). Retrieved July 23, 2016, from https://www.owasp.org/index.php/Session_hijacking_attack

- [RFC 7519 - **JSON Web Token (JWT)** - IETF](https://tools.ietf.org/html/rfc7519). (2015, May). Retrieved July 23, 2016, from https://tools.ietf.org/html/rfc7519

- [**Critical vulnerabilities in JSON Web Token libraries** - Auth0](https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/). (2015, March 31). Retrieved July 23, 2016, from https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/

- [RFC 6749 - **The OAuth 2.0 Authorization Framework** - IETF](https://tools.ietf.org/html/rfc6749). (2012, October). Retrieved July 23, 2016, from https://tools.ietf.org/html/rfc6749

- [**OpenID Connect Core 1.0 incorporating errata set 1** - OpenID Foundation](http://openid.net/specs/openid-connect-core-1_0.html). (2014, November 8). Retrieved July 23, 2016, from http://openid.net/specs/openid-connect-core-1_0.html

- [**Cookies vs. Tokens: The Definitive Guide** - DZone Integration](https://dzone.com/articles/cookies-vs-tokens-the-definitive-guide). (2016, June 2). Retrieved July 23, 2016, from https://dzone.com/articles/cookies-vs-tokens-the-definitive-guide
