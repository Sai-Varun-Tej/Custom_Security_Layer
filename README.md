# Custom Security Layer (CSL)

A TLS-inspired secure transport protocol built from scratch over raw TCP
sockets, followed by an encrypted 1-to-1 terminal chat application.

## Overview

This project implements a custom secure communication protocol over raw
TCP sockets.

The goal was to understand what happens underneath a secure connection
instead of relying on a high-level secure-channel API such as TLS
sockets.

The protocol was built incrementally through Levels 1--6:

1.  TCP communication and custom message framing
2.  Diffie-Hellman key exchange
3.  Key derivation
4.  Handshake confirmation
5.  AES-GCM encrypted and authenticated messaging
6.  Interactive 1-to-1 terminal chat

The implementation uses OpenSSL for cryptographic primitives, while the
protocol logic, framing, handshake flow, key derivation and message
handling are implemented as part of this project.

> **Scope:** This implementation focuses on Levels 1--6.

------------------------------------------------------------------------

# Architecture

``` text
TCP Connection
      ↓
DH Key Exchange
      ↓
Shared Secret
      ↓
Key Derivation
      ↓
Encryption Key + MAC Key
      ↓
Handshake Confirmation
      ↓
Secure Messaging
```

## Technologies Used

-   C++
-   TCP sockets
-   OpenSSL 3
-   Diffie-Hellman
-   SHA-256
-   HMAC-SHA256
-   AES-256-GCM
-   Linux/WSL
-   Git/GitHub

## Project Structure

``` text
CSL/
├── level-1/
│   ├── client.cpp
│   └── server.cpp
├── level-2/
│   ├── client.cpp
│   └── server.cpp
├── level-3/
│   ├── client.cpp
│   └── server.cpp
├── level-4/
│   ├── client.cpp
│   └── server.cpp
├── level-5/
│   ├── client.cpp
│   └── server.cpp
└── level-6/
    ├── client.cpp
    └── server.cpp
```

# Level 1 --- TCP Plumbing and Message Framing

TCP provides a **byte stream**, not individual messages.

For example, separate sends such as:

``` text
send("Hello")
send("LOGIN")
send("GOODBYE")
```

are not guaranteed to arrive as three separate messages.

Therefore, I designed the following custom frame:

``` text
+------+--------+---------+
| Type | Length | Payload |
+------+--------+---------+
   1B      4B        N B
```

-   `Type` identifies the message type.
-   `Length` specifies the payload size.
-   `Payload` contains the actual data.

I implemented `send_all()`, `recv_all()`, `send_frame()` and
`recv_frame()` to correctly handle TCP's stream behaviour and partial
sends/receives.

I tested messages with different types and lengths in both directions.

# Level 2 --- Diffie-Hellman Key Exchange

Both client and server generate their own DH keypairs.

``` text
Client                         Server

Private A                       Private B
Public A                        Public B

       Public A  ──────────→

       ←────────── Public B

Shared Secret                   Shared Secret
      S                               S
```

Both sides independently calculate the same shared secret without
transmitting the secret itself.

I used OpenSSL's EVP interface and the FFDHE2048 group.

The public key is serialized before transmission and deserialized on the
receiving side.

One important learning was that an `EVP_PKEY` is an in-memory OpenSSL
object and cannot simply be sent over TCP. Only its serialized
public-key representation is transmitted.

# Level 3 --- Key Derivation

The raw DH shared secret should not be used directly as an application
key.

I implemented a simple custom KDF using SHA-256 with domain-separated
labels:

``` text
Shared Secret
      │
      ├── SHA-256("ENC" || Shared Secret)
      │              ↓
      │        Encryption Key
      │
      └── SHA-256("MAC" || Shared Secret)
                     ↓
                 MAC Key
```

This is a real derivation function rather than simple truncation or
copying of the DH secret.

Both sides independently derive identical keys from the same shared
secret.

HKDF was not implemented .

# Level 4 --- Handshake Confirmation

Before application messages are exchanged, both sides confirm that the
handshake completed consistently.

I implemented HMAC-SHA256 using the derived MAC key.

The transcript contains:

``` text
CSL-HS-V1
+
Client public key length
+
Client public key
+
Server public key length
+
Server public key
```

Both sides calculate an HMAC over this transcript and verify the
confirmation received from the peer.

If a DH public value is tampered with, the handshake state changes and
confirmation fails rather than allowing communication to continue with
mismatched key material.

# Level 5 --- Encrypted and Authenticated Messaging

For application data, I chose **AES-256-GCM**.

AES-GCM is an AEAD mode, so it provides encryption and authentication
together. A separate MAC is therefore not required for the application
messages.

The message protection flow is:

``` text
Plaintext
    +
Encryption Key
    +
Fresh Nonce
    ↓
AES-256-GCM
    ↓
Ciphertext + Authentication Tag
```

Each encrypted payload is:

``` text
+----------+----------------+----------+
|  Nonce   |  Ciphertext    |   Tag    |
|  12 bytes|      N bytes   | 16 bytes |
+----------+----------------+----------+
```

This is placed inside the custom Level 1 frame.

Encrypted application data uses frame type `5`.

A fresh 12-byte nonce is generated for every encrypted message. The
nonce is transmitted openly, but the same nonce must never be reused
with the same AES-GCM key.

If the ciphertext, nonce or authentication tag is modified, GCM
authentication fails and the message is rejected.

# Level 6 --- 1-to-1 Chat Application

Level 6 combines all previous levels into a usable terminal chat
application.

The handshake runs automatically when the connection is established.

``` text
TCP
 ↓
DH
 ↓
KDF
 ↓
Handshake Confirmation
 ↓
Secure Channel
 ↓
Interactive Chat
```

When a user types a message:

``` text
Plaintext
   ↓
AES-256-GCM
   ↓
Nonce + Ciphertext + Tag
   ↓
Custom Frame
   ↓
TCP
```

The receiver performs the reverse process:

``` text
TCP
 ↓
Frame
 ↓
Extract Nonce
 ↓
Extract Ciphertext
 ↓
Extract Tag
 ↓
AES-GCM Decryption + Authentication
 ↓
Plaintext
 ↓
Display
```

## Simultaneous Sending and Receiving

A simple `getline()` loop would block while waiting for keyboard input,
preventing the application from immediately processing incoming
messages.

Therefore, Level 6 uses `select()` to monitor both:

``` text
stdin
socket
```

This allows the application to send and receive messages interactively.

# Security Properties Achieved

The completed Levels 1--6 provide:

### Confidentiality

Application messages are encrypted using AES-256-GCM.

### Integrity / Tamper Detection

AES-GCM authentication tags detect modifications to encrypted messages.

### Key Establishment

The encryption key is derived from a fresh DH exchange rather than being
hardcoded or pre-shared.

### Key Separation

The DH shared secret is passed through a KDF to derive separate
encryption and MAC keys.

### Handshake Confirmation

The protocol verifies the handshake before application messages are
exchanged.

### Custom Framing

The protocol defines its own message framing instead of relying on TCP
message boundaries.

# Important Limitation

This project does **not** implement peer identity authentication.

The specification states that certificates and identity verification are
not required.

Therefore, the current protocol establishes a secure session with the
party at the other end of the socket, but it does not prove that the
peer is a particular real-world identity.

An active MITM could potentially establish separate DH exchanges with
the client and server.

This is the problem addressed by the optional PKI/identity extension in
Level 8.

# Challenges and Debugging

This project was not a straightforward implementation for me. A
significant part of the learning came from understanding why things
failed rather than only getting the final code to work.

## 1. Understanding TCP as a Byte Stream

Initially, I had to understand why simply using `send()` and `recv()`
was not enough.

I learned that TCP does not preserve application-level message
boundaries.

This led to implementing the custom framing layer and `send_all()` /
`recv_all()`.

## 2. Understanding TCP and Socket Programming

I spent time understanding:

-   `socket()`
-   `bind()`
-   `listen()`
-   `accept()`
-   `connect()`
-   TCP file descriptors
-   IP addresses and ports
-   network byte order
-   `htons()` / `ntohl()`
-   `inet_pton()`

Some of these concepts were initially unfamiliar, so I tested the
networking layer independently before moving to cryptography.

## 3. OpenSSL EVP Interface

OpenSSL was one of the more difficult parts of the project.

I had to understand the difference between:

``` text
EVP_PKEY
EVP_PKEY_CTX
EVP_MD_CTX
```

and how OpenSSL represents cryptographic operations internally.

Understanding these objects helped me work with DH and SHA-256 rather
than treating OpenSSL as a black box.

## 4. DH Public-Key Serialization

The OpenSSL DH keypair cannot be sent directly through TCP.

I had to serialize the public key:

``` text
EVP_PKEY
    ↓
i2d_PUBKEY()
    ↓
bytes
    ↓
TCP
```

and reconstruct it using:

``` text
bytes
  ↓
d2i_PUBKEY()
  ↓
EVP_PKEY
```

This helped me understand the difference between an in-memory
cryptographic object and its network representation.

## 5. OpenSSL Errors

I encountered several OpenSSL errors while implementing DH.

One important issue was calling:

``` text
EVP_PKEY_derive_set_peer()
```

before:

``` text
EVP_PKEY_derive_init()
```

This resulted in an OpenSSL operation error.

The correct order is:

``` text
EVP_PKEY_CTX_new()
        ↓
EVP_PKEY_derive_init()
        ↓
EVP_PKEY_derive_set_peer()
        ↓
EVP_PKEY_derive()
```

I also encountered smaller implementation issues while working with
sockets, OpenSSL APIs and the development environment. Debugging these
issues helped me understand the APIs instead of simply working around
errors.

## 6. Shared Secret Derivation

Another debugging point was understanding that `EVP_PKEY_derive()` is
used in two stages:

``` text
First:
determine required output size

Second:
actually derive the shared secret
```

This helped me understand why the function is called twice.

## 7. KDF and Key Separation

Initially, concepts such as KDF, MAC, encryption keys, authentication
tags and AES-GCM were confusing because they are related but serve
different purposes.

The project helped me understand:

``` text
DH
 ↓
Shared Secret
 ↓
KDF
 ├── Encryption Key
 └── MAC Key
```

and later:

``` text
Encryption Key
      ↓
   AES-GCM
   ├── Ciphertext
   └── Authentication Tag
```

The MAC key is used for Level 4 handshake confirmation, while AES-GCM
provides authentication for application messages.

## 8. Understanding AES-GCM

I initially had to understand why AES-GCM produces both ciphertext and
an authentication tag, and why the tag is transmitted rather than kept
secret.

I learned that the tag does not need to be secret. The encryption key is
the secret, and the receiver independently verifies the tag using that
key.

## 9. Level 6 Blocking Problem

A normal:

``` cpp
getline(cin, message);
```

blocks while waiting for keyboard input.

That is not suitable for a chat application because the other side may
send a message during this time.

I therefore learned and used `select()` to monitor both stdin and the
socket simultaneously.

This was an important step in converting the previous networking
experiments into an actual chat application.

# Design Decisions

## Why DH?

DH allows both parties to establish a shared secret without transmitting
the secret itself.

The project specifically required Diffie-Hellman, so I implemented it
using OpenSSL's EVP interface.

## Why a Custom KDF?

The specification requires a real key derivation function but does not
require a standard KDF.

I used SHA-256 with domain-separated labels:

``` text
"ENC" || shared_secret
"MAC" || shared_secret
```

This satisfies the required Level 3 functionality.

HKDF was left as a bonus.

## Why AES-GCM?

The project allows either encryption + MAC or an AEAD mode such as
AES-GCM.

I chose AES-256-GCM because it provides encryption and authentication
together and avoids having to separately implement message-level
encryption and MAC handling.

## Why Not Implement the Bonus Levels?

The main objective of the project was to understand and implement the
core secure transport and chat application.

I focused on completing Levels 1--6 properly rather than extending the
project to Levels 7 and 8.

The bonus levels would require additional protocol design involving:

-   multi-party session management
-   multiple independent session keys
-   group key establishment
-   certificates
-   long-term identity keys
-   digital signatures
-   CA verification


# What I Learned

This project significantly improved my understanding of systems,
networking and cryptography.

Some of the major concepts I learned by implementing them were:

-   TCP is a byte stream.
-   Application protocols need their own framing.
-   TCP sockets are represented using file descriptors.
-   `send()` and `recv()` may process partial data.
-   DH establishes a shared secret without sending the secret itself.
-   Public keys need serialization before being transmitted.
-   Raw DH output should not directly be used as an application key.
-   KDFs derive purpose-specific key material.
-   HMAC provides integrity/authentication using a secret key.
-   AES-GCM provides authenticated encryption.
-   Nonces must be handled correctly.
-   Authentication tags allow tampering to be detected.
-   `select()` can be used to handle multiple input sources.
-   A secure channel and identity authentication are different problems.

Most importantly, I learned how the individual components fit together
rather than studying them as isolated concepts.

# Final Protocol Flow

``` text
Client                                Server
  │                                      │
  │──────── TCP Connection ──────────────│
  │                                      │
  │────── DH Public Key ────────────────→│
  │                                      │
  │←───── DH Public Key ────────────────│
  │                                      │
  │       Derive Shared Secret           │
  │       Derive ENC + MAC Keys          │
  │                                      │
  │──── Handshake Confirmation ─────────→│
  │                                      │
  │←─── Handshake Confirmation ──────────│
  │                                      │
  │          Secure Channel              │
  │                                      │
  │──── Encrypted Chat Message ─────────→│
  │                                      │
  │←─── Encrypted Chat Message ──────────│
  │                                      │
  │──── Encrypted Chat Message ─────────→│
  │                                      │
  │               ...                    │
  │                                      │
```

Each application message is protected as:

``` text
Plaintext
    │
    ▼
AES-256-GCM
    │
    ├── Fresh Nonce
    ├── Ciphertext
    └── Authentication Tag
    │
    ▼
Custom TCP Frame
    │
    ▼
TCP
```

# Project Status

  Level                                Status
  ------------------------------------ -----------------
  Level 1 --- TCP + Framing            Completed
  Level 2 --- Diffie-Hellman           Completed
  Level 3 --- Key Derivation           Completed
  Level 4 --- Handshake Confirmation   Completed
  Level 5 --- AES-GCM Messaging        Completed
  Level 6 --- 1-to-1 Chat              Completed
  Level 7 --- Chat Room                Not implemented
  Level 8 --- PKI                      Not implemented

The project intentionally focuses on the complete core implementation
through Level 6.

## Demonstrations

### Intermediate Implementation

- Level 1 --- TCP and framing
- Level 2 --- DH exchange
- Level 3 --- KDF [Level 1, 2, 3](https://drive.google.com/file/d/18SPKq9U-YiE-1KC-NKOeuoKyjZzZznIA/view?usp=drive_link)
- Level 4 --- Handshake confirmation [Level 4](https://drive.google.com/file/d/1llxyOQwB7noGDtuc-94Qxlj_xFuXM7pg/view?usp=drive_link)
- Level 5 --- AES-GCM
- Level 6 --- Secure 1-to-1 Chat [Level 5, 6](https://drive.google.com/file/d/1OCv7uArvBa9fUa8x5A6S5KXkOLukXRsN/view?usp=drive_link)

### Final Demonstration

[Complete Demo](https://drive.google.com/file/d/1LWOpvq4hyYf1b7XM4wc5qmJdK13vlYqB/view?usp=drive_link)

# Conclusion

The main purpose of this project was not simply to create an encrypted
chat application, but to understand the components that make a secure
transport protocol work.

Starting from raw TCP sockets, I progressively built:

``` text
TCP
 ↓
Framing
 ↓
DH
 ↓
KDF
 ↓
Handshake Confirmation
 ↓
AES-GCM
 ↓
Interactive Secure Chat
```

Working through the implementation and debugging each layer helped me
understand the relationship between networking, cryptography and systems
programming much more deeply than simply using an existing TLS library.

The final result is a custom TLS-inspired secure transport protocol
running over raw TCP and powering a 1-to-1 encrypted terminal chat
application.

---

**Sai Varun Tej K**
