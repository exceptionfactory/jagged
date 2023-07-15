# Jagged

Java implementation of age encryption

[![build](https://github.com/exceptionfactory/jagged/actions/workflows/build.yml/badge.svg)](https://github.com/exceptionfactory/jagged/actions/workflows/build.yml)
[![codecov](https://codecov.io/gh/exceptionfactory/jagged/branch/main/graph/badge.svg?token=SM7PEI00HT)](https://codecov.io/gh/exceptionfactory/jagged)
[![age-encryption.org specification](https://img.shields.io/badge/age--encryption.org-v1-blueviolet)](https://age-encryption.org/v1)

# Build Requirements

- Java 17
- Maven 3.9

# Runtime Requirements

- Java 17 or 11
- Java 8 with [Bouncy Castle Security Provider](https://bouncycastle.org/docs/docs1.8on/org/bouncycastle/jce/provider/BouncyCastleProvider.html)

## Java Cryptography Architecture

Jagged uses the
[Java Cryptography Architecture](https://docs.oracle.com/en/java/javase/11/security/java-cryptography-architecture-jca-reference-guide.html)
framework for the following algorithms:

- `ChaCha20-Poly1305` with [javax.crypto.Cipher](https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html)
- `HmacSHA256` with [javax.crypto.Mac](https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Mac.html)
- `PBKDF2WithHmacSHA256` with [javax.crypto.SecretKeyFactory](https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/SecretKeyFactory.html)
- `X25519` with [javax.crypto.KeyAgreement](https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/KeyAgreement.html)
- `X25519` with [java.security.KeyFactory](https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/security/KeyFactory.html)
- `X25519` with [java.security.KeyPairGenerator](https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/security/KeyPairGenerator.html)

[JEP 324](https://openjdk.org/jeps/324) introduced X25519 Key Agreement in Java 11. 
[JEP 329](https://openjdk.org/jeps/329) added ChaCha20-Poly1305 in Java 11.

Jagged does not require additional dependencies when running on Java 11 or higher.

Jagged on Java 8 requires an additional
[Security Provider](https://docs.oracle.com/javase/8/docs/api/java/security/Provider.html)
to support X25519 and ChaCha20-Poly1305.

## Bouncy Castle Security Provider

The [Bouncy Castle](https://bouncycastle.org/java.html) framework includes the
[BouncyCastleProvider](https://bouncycastle.org/docs/docs1.8on/org/bouncycastle/jce/provider/BouncyCastleProvider.html)
which can be installed to support using Jagged on Java 8.

The `jagged-x25519` library requires access to X25519 encoded keys. The default behavior of the Bouncy Castle library
includes the public key together with the private key in the encoded representation, which differs from the standard
Java implementation. The following Java System property must be enabled when using the Bouncy Castle Provider:

```
org.bouncycastle.pkcs8.v1_info_only
```

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

## jagged-bech32

The `jagged-bech32` module contains an implementation of the Bech32 encoding specification defined according to
[Bitcoin Improvement Proposal 0173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki). Bech32 encoding
supports a standard representation of X25519 private and public keys. The `Bech32` class follows the pattern of
[java.util.Base64](https://docs.oracle.com/javase/8/docs/api/java/util/Base64.html) and encloses `Bech32.Decoder` and
`Bech32.Encoder` interfaces. Bech32 encoding consists of a Human-Readable Part prefix, a separator, and data part that
ends with a checksum.

## jagged-framework

The `jagged-framework` module includes shared components for common cryptographic operations.

The `stream` package includes the `StandardDecryptingChannelFactory` and `StandardEncryptingChannelFactory` classes,
which implement the corresponding public interfaces for streaming cipher operations.

The `armor` packaged includes the `ArmoredReadableByteChannel` and `ArmoredWritableByteChannel` classes, supporting
reading and writing ASCII armored files with standard PEM header and footer lines.

## jagged-scrypt

The `jagged-scrypt` module supports encryption and decryption using a passphrase and configurable work factor.

The `ScryptRecipientStanzaReaderFactory` creates instances of `RecipientStanzaReader` using a passphrase.

The `ScryptRecipientStanzaWriterFactory` creates instances of `RecipientStanzaWriter` using a passphrase and 
a work factor with a minimum value of 2 and a maximum value of 20.

The module includes a custom implementation of the scrypt key derivation function with predefined settings that
match age encryption scrypt recipient specifications.

## jagged-x25519

The `jagged-x25519` module supports encryption and decryption using public and private key pairs. Key generation and
key agreement functions use the Java Cryptography Architecture framework. Key encoding and decoding functions use the
`jagged-bech32` library.

The `X25519KeyPairGenerator` class implements
[java.security.KeyPairGenerator](https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/security/KeyPairGenerator.html)
and returns public and private key pairs encoded using Bech32.

The `X25519RecipientStanzaReaderFactory` creates instances of `RecipientStanzaReader` using a private key encoded using
Bech32. Encoded private keys begin with `AGE-SECRET-KEY-1` as the Bech32 Human-Readable Part and separator.

The `X25519RecipientStanzaWriterFactory` creates instances of `RecipientStanzaWriter` using a public key encoded using
Bech32. Encoded public keys begin with `age1` as the Bech32 Human-Readable Part and separator.

## jagged-test

The `jagged-test` module includes framework tests for [age test vectors](https://github.com/C2SP/CCTV/tree/main/age)
defined in the [Community Cryptography Test Vectors](https://github.com/C2SP/CCTV) project. The
`CommunityCryptographyTest` runs a test method for each file in the test data directory. The `FrameworkTest` class
exercises binary and armored encryption and decryption methods using supported recipient types.

# Building

Run the following Maven command to build the libraries:

```
./mvnw clean install
```

# Licensing

Jagged is released under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).
