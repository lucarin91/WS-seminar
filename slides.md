# Authentication Methods in Modern Web Applications
### WS - Seminar

<small>Created by [Luca Rinaldi](http://lucar.in)</small>



# Agenda
- HTTP Authentication Framework

- Session Authentication Systems

- Token Authentication Systems

- Token vs Session

- Conclusions



# HTTP Authentication Framework
Originally standardized in **rfc2617** by IETF(Internet Engineering Task Force) and than updated with:

- rfc7617 "The 'Basic' HTTP Authentication Scheme"

- rfc7616 "HTTP Digest Access Authentication"

- rfc6750 "The OAuth 2.0 Authorization Framework: Bearer Token Usage"


## Basic HTTP Authentication *[rfc7617]*
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
It's a challenge response system, where the password is not transmitted in clear text.

The server send a random `nonce` and the client reply with `hash(user:password:nonce)`

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


## Bearer Token *[rfc6750]*
A security token with the property that any party in possession of
the token (a "bearer") can use.

Using a bearer token does not require a bearer to prove possession of cryptographic key material (proof-of-possession).

```
GET /resource HTTP/1.1
Host: server.example.com
Authorization: Bearer mF_9.B5f-4.1JqM
```



# HTTP is stateless
We want to avoid to communicate at every request username and password.

We want to save and retrieve specific data for every logged users.

note:
HTML is a stateless protocol, but usually application needs to keep information between two distinct calls.



# Web Session Manager
With HTTP/1.1 and CGI programming language and framework start to implement Web Session Manager.

They maintain session with the users and identified it with a **sessionID**.

note:
https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol#HTTP_session
https://en.wikipedia.org/wiki/Common_Gateway_Interface

is important that the sessionID is:
- highly random, to avoid prediction
- sufficient long, to avoid brute force attack (>= 50 character)


## Web Session Flow
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
it uses cookies to store sessionID on the client, than at each connection retrieve it from an hash-table inside the web server.

http://machinesaredigging.com/2013/10/29/how-does-a-web-session-work/


## Web Session PHP example
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



# Web Session security issue
- Session Hijacking thought:
    - observation
    - brute force
    - XSS

- CSRF (Cross-site request forgery), because it relies on cookies

note:
CSRF, the site can be put in iframe, generate a POST request and re-use the existing authentication cookie to another request.
https://www.owasp.org/index.php/Session_hijacking_attack



# Session limitation
- Centralize information

- Memory and cpu overhead

- Can't work with Cross Domain and CORS (Cross-origin resource sharing)

- Simple authentication flow



# Tokens
It is a string that contain security credential to a login session.

It can be of two types:
- self-contained token
- opaque token

note:
- self-contained token, These are tokens that conform to the JSON Web Token standard and contain information about an identity in the form of claims. They are self-contained in that it is not necessary for the recipient to call a server to validate the token.

- Opaque tokens, Opaque tokens are tokens in a proprietary format that typically contain some identifier to information in a server’s persistent storage. To validate an opaque token, the recipient of the token needs to call the server that issued the token.



# JSON Web Token *[rfc7519]*
It is a self-contained token with a set of keys/value pairs in JSON format.

It safeguard its integrity with JSON Web Signature (JWS) or JSON Web Encryption (JWE)

Am example of JWT:
```JSON
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
.
eyJpc3MiOiJsdWNhci5pbiIsImV4cCI6MTQ2OTI2ODcwOSwibmFtZSI6Imx1Y2EiLCJhZG1pbiI6dHJ1ZX0
.
5Z5tKUacfE-r_L56uaddeimgREpgk39Fbx6EJ3cuTJg
```

note:
JSON Web Token (JWT) is a compact claims representation format intended for space constrained environments such as HTTP Authorization headers and URI query parameters. JWTs encode claims to be transmitted as a JSON [RFC7159] object that is used as the payload of a JSON Web Signature (JWS) [JWS] structure or as the plaintext of a JSON Web Encryption (JWE) [JWE] structure, enabling the claims to be digitally signed or integrity protected with a Message Authentication Code (MAC) and/or encrypted. JWTs are always represented using the JWS Compact Serialization or the JWE Compact Serialization.


## JWT Structure
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


## JWT Authentication Flow
<pre>

         +---------+                              +---------+
         |         |   (A) POST /authenticate     |         |
         |         +------------------------------>         +--------+
         |         |  [username=..&password=..]   |         |  (B)   |
         |         |                              |         |Generate|
         |         |   (C) HTTP 200 OK            |         |  JWT   |
         |         <------------------------------+         <--------+
         |         |      [token: '..JWT..']      |         |
         |         |                              |   Web   |
         | Client  |                              |  Server |
         |         |                              |         |
         |         |   (D) HTTP GET               |         |
         |         +------------------------------>         +--------+
         |         | [Authentication: Bearer JWT] |         |  (E)   |
         |         |                              |         |Validate|
         |         |   (F) HTTP 200 OK            |         |  JWT   |
         |         <------------------------------+         <--------+
         |         |                              |         |
         +---------+                              +---------+

</pre>



# OAuth 2.0 *[rfc6749]*
It enables a third-party application to obtain limited access to a service in behalf of a user.

Three parties:
- resource owner (end-user)

- client (third-party application)

- resource and authorization server (service)

For example: </br>
*Draw.io, an online flow chart editor, that request the user to access their storage space on Dropbox, to save and load files.* <!-- .element: style="font-size: 26px"-->

note:
- resource owner, An entity capable of granting access to a protected resource. When the resource owner is a person, it is referred to as an end-user.

- resource server, The server hosting the protected resources, capable of accepting and responding to protected resource requests using access tokens.

- client, An application making protected resource requests on behalf of the resource owner and with its authorization.  The term "client" does not imply any particular implementation characteristics (e.g., whether the application executes on a server, a desktop, or other devices).

- authorization server, The server issuing access tokens to the client after successfully     authenticating the resource owner and obtaining authorization.


## OAuth Authentication Flow
<pre>

        +----------+
        | Resource |
        |   Owner  |
        |          |
        +----------+
             ^
             |
            (B)
        +----|-----+          Client Identifier      +---------------+
        |         -+----(A)-- & Redirection URI ---->|               |
        |  User-   |                                 | Authorization |
        |  Agent  -+----(B)-- User authenticates --->|     Server    |
        |          |                                 |               |
        |         -+----(C)-- Authorization Code ---<|               |
        +-|----|---+                                 +---------------+
          |    |                                         ^      v
         (A)  (C)                                        |      |
          |    |                                         |      |
          ^    v                                         |      |
        +---------+                                      |      |
        |         |>---(D)-- Authorization Code ---------'      |
        |  Client |          & Redirection URI                  |
        |         |                                             |
        |         |<---(E)----- Access Token -------------------'
        +---------+       (w/ Optional Refresh Token)

</pre>

note:
(A) The client initiates the flow by directing the resource owner's user-agent to the authorization endpoint. The client includes its client identifier, requested scope, local state, and a redirection URI to which the authorization server will send the user-agent back once access is granted (or denied).

(B) The authorization server authenticates the resource owner (via the user-agent) and establishes whether the resource owner grants or denies the client's access request.

(C) Assuming the resource owner grants access, the authorization server redirects the user-agent back to the client using the redirection URI provided earlier (in the request or during client registration). The redirection URI includes an authorization code and any local state provided by the client earlier.

(D) The client requests an access token from the authorization server's token endpoint by including the authorization code received in the previous step. When making the request, the client authenticates with the authorization server. The client includes the redirection URI used to obtain the authorization code for verification.

(E) The authorization server authenticates the client, validates the authorization code, and ensures that the redirection URI received matches the URI used to redirect the client in step (C). If valid, the authorization server responds back with an access token and, optionally, a refresh token.



# Token Security issue
- XSS, it's possible to steal saved token

- Invalidation system prone to error

- They can contain sensible information

note:
we can't use `HttpOnly` cookie flag


# Why use Token
- Scalable

- Efficient (memory and CPU)

- CSRF immune

- Work with Cross Domain and CORS (Cross-origin resource sharing)

- Mobile ready



# Conclusions
If correctly implemented either web session or token system can have strong security.

The type of authentication system really dependence on the goal of the project.

But token mechanisms are more general and ready for mobile and modern web application.



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

- [**Cookies vs. Tokens: The Definitive Guide** - DZone Integration](https://dzone.com/articles/cookies-vs-tokens-the-definitive-guide). (2016, June 2). Retrieved July 23, 2016, from https://dzone.com/articles/cookies-vs-tokens-the-definitive-guide
