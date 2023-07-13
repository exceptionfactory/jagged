# Jagged

Java implementation of age encryption

[![build](https://github.com/exceptionfactory/jagged/actions/workflows/build.yml/badge.svg)](https://github.com/exceptionfactory/jagged/actions/workflows/build.yml)
[![codecov](https://codecov.io/gh/exceptionfactory/jagged/branch/main/graph/badge.svg?token=SM7PEI00HT)](https://codecov.io/gh/exceptionfactory/jagged)
[![age-encryption.org specification](https://img.shields.io/badge/age--encryption.org-v1-blueviolet)](https://age-encryption.org/v1)

# Build Requirements

- Java 11
- Maven 3.9

# Versioning

Jagged follows the [Semantic Versioning Specification 2.0.0](https://semver.org/).

# Features

Jagged supports streaming encryption and decryption using standard recipient types.

- Encryption and decryption of [binary age files](https://github.com/C2SP/C2SP/blob/main/age.md#encrypted-file-format)
- Encryption and decryption of [armored age files](https://github.com/C2SP/C2SP/blob/main/age.md#ascii-armor)
- [X25519](https://github.com/C2SP/C2SP/blob/main/age.md#the-x25519-recipient-type) recipients and identities
- [scrypt](https://github.com/C2SP/C2SP/blob/main/age.md#the-scrypt-recipient-type) recipients and identities

# Specifications

Jagged supports version 1 of the [age-encryption.org](https://age-encryption.org/v1) specification.

The age encryption specification builds on a number of common cryptographic algorithms and encoding standards.

## Formatting Standards

Files encrypted using the age specification include a textual
[header](https://github.com/C2SP/C2SP/blob/main/age.md#header) and binary
[payload](https://github.com/C2SP/C2SP/blob/main/age.md#payload).

File headers include a [message authentication code](https://github.com/C2SP/C2SP/blob/main/age.md#header-mac) computed
using HMAC-SHA-256.

- [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104.html) HMAC: Keyed-Hashing for Message Authentication

File headers include [recipient stanza](https://github.com/C2SP/C2SP/blob/main/age.md#recipient-stanza) binary body
elements encoded using Base64 Canonical Encoding.

- [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648.html) The Base16, Base32, and Base64 Data Encodings

File payloads use a key derived using HKDF-SHA-256.

- [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html) HMAC-based Extract-and-Expand Key Derivation Function (HKDF)

File payload encryption uses ChaCha20-Poly1305 for as the algorithm for Authenticated Encryption with Additional Data.

- [RFC 7539](https://www.rfc-editor.org/rfc/rfc7539.html) ChaCha20 and Poly1305 for IETF Protocols

## Recipient Standards

Standard recipient types include asymmetric encryption using 
[X25519](https://github.com/C2SP/C2SP/blob/main/age.md#the-x25519-recipient-type) and passphrase encryption using
[scrypt](https://github.com/C2SP/C2SP/blob/main/age.md#the-scrypt-recipient-type).

The X25519 type uses Curve25519 for Elliptic Curve Diffie-Hellman shared secret key exchanges.

- [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html) Elliptic Curves for Security

The X25519 type uses Bech32 for encoding public keys and private keys.

- [BIP 0173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) Base32 address format

The X25519 type encrypts a File Key with ChaCha20-Poly1305 using a key derived with HKDF-SHA-256.

The scrypt type uses a passphrase and configurable work factor with other preset values to derive the key for encrypting
a File Key.

- [RFC 7914](https://www.rfc-editor.org/rfc/rfc7914.html) The scrypt Password-Based Key Derivation Function

The scrypt type encrypts a File Key with ChaCha20-Poly1305.

# Modules

Jagged consists of multiple modules supporting different aspects of the age encryption specification.

- jagged-api
- jagged-bech32
- jagged-framework
- jagged-scrypt
- jagged-test
- jagged-x25519

## jagged-api

The `jagged-api` module contains the core public interfaces for encryption and decryption operations. The module
contains interfaces and classes in the `com.exceptionfactory.jagged` package, which provide integration and extension
points for other components.

The `FileKey` class implements [java.crypto.SecretKey](https://docs.oracle.com/javase/8/docs/api/javax/crypto/SecretKey.html)
and supports the primary contract for age identities and recipients.

The `RecipientStanza` interface follows the pattern of the age [Stanza](https://pkg.go.dev/filippo.io/age#Stanza),
providing access to the Type, Arguments, and binary Body elements.

The `RecipientStanzaReader` interface serves as the age [Identity](https://pkg.go.dev/filippo.io/age#Identity) 
abstraction, responsible for reading `RecipientStanza` objects and return a decrypted `FileKey`.

The `RecipientStanzaWriter` interface follows the age [Recipient](https://pkg.go.dev/filippo.io/age#Recipient)
abstraction, responsible for wrapping a `FileKey` and returning a collection of `RecipientStanza` objects.

The `EncryptingChannelFactory` interface wraps a provided
[WritableByteChannel](https://docs.oracle.com/javase/8/docs/api/java/nio/channels/WritableByteChannel.html) and returns
a `WritableByteChannel` that supports streaming encryption to one or more recipients based on supplied
`RecipientStanzaWriter` instances.

The `DecryptingChannelFactory` interface wraps a provided
[ReadableByteChannel](https://docs.oracle.com/javase/8/docs/api/java/nio/channels/ReadableByteChannel.html) and returns
a `ReadableByteChannel` that supports streaming decryption for a matched identity based on supplied
`RecipientStanzaReader` instances.

# Building

Run the following Maven command to build the libraries:

```
./mvnw clean install
```

# Licensing

Jagged is released under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).
