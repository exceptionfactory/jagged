# Jagged

Java implementation of age encryption

[![build](https://github.com/exceptionfactory/jagged/actions/workflows/build.yml/badge.svg)](https://github.com/exceptionfactory/jagged/actions/workflows/build.yml)
[![codecov](https://codecov.io/gh/exceptionfactory/jagged/branch/main/graph/badge.svg?token=SM7PEI00HT)](https://codecov.io/gh/exceptionfactory/jagged)
[![vulnerabilities](https://snyk.io/test/github/exceptionfactory/jagged/badge.svg)](https://snyk.io/test/github/exceptionfactory/jagged)
[![javadoc](https://javadoc.io/badge2/com.exceptionfactory.jagged/jagged-api/javadoc.svg)](https://javadoc.io/doc/com.exceptionfactory.jagged/jagged-api)
[![maven-central](https://img.shields.io/maven-central/v/com.exceptionfactory.jagged/jagged-api)](https://central.sonatype.com/artifact/com.exceptionfactory.jagged/jagged-api)
[![age-encryption.org specification](https://img.shields.io/badge/age--encryption.org-v1-blueviolet)](https://age-encryption.org/v1)

# Build Requirements

- Java 21
- Maven 3.9

# Runtime Requirements

- Java 21, 17, or 11
- Java 8 with [Bouncy Castle Security Provider](https://bouncycastle.org/docs/docs1.8on/org/bouncycastle/jce/provider/BouncyCastleProvider.html)

## Java Cryptography Architecture

Jagged uses the
[Java Cryptography Architecture](https://docs.oracle.com/en/java/javase/17/security/java-cryptography-architecture-jca-reference-guide.html)
framework for the following algorithms:

- `ChaCha20-Poly1305` with [javax.crypto.Cipher](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/javax/crypto/Cipher.html)
- `HmacSHA256` with [javax.crypto.Mac](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/javax/crypto/Mac.html)
- `PBKDF2WithHmacSHA256` with [javax.crypto.SecretKeyFactory](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/javax/crypto/SecretKeyFactory.html)
- `RSA` with [java.security.KeyFactory](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyFactory.html)
- `RSA/ECB/OAEPPadding` with [javax.crypto.Cipher](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/javax/crypto/Cipher.html)
- `X25519` with [javax.crypto.KeyAgreement](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/javax/crypto/KeyAgreement.html)
- `X25519` with [java.security.KeyFactory](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyFactory.html)
- `X25519` with [java.security.KeyPairGenerator](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyPairGenerator.html)

[JEP 324](https://openjdk.org/jeps/324) introduced X25519 Key Agreement in Java 11. 
[JEP 329](https://openjdk.org/jeps/329) added ChaCha20-Poly1305 in Java 11.

Jagged does not require additional dependencies when running on Java 11 or higher.

Jagged on Java 8 requires an additional
[Security Provider](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/Provider.html)
to support X25519 and ChaCha20-Poly1305.

## Bouncy Castle Security Provider

The [Bouncy Castle](https://bouncycastle.org/java.html) framework includes the
[BouncyCastleProvider](https://bouncycastle.org/docs/docs1.8on/org/bouncycastle/jce/provider/BouncyCastleProvider.html)
which can be installed to support using Jagged on Java 8.

The `jagged-x25519` library requires access to X25519 encoded keys. The default behavior of the Bouncy Castle library
includes the public key together with the private key in the encoded representation, which differs from the standard
Java implementation. The Jagged library provides conversion between encoded formats.

# Versioning

Jagged follows the [Semantic Versioning Specification 2.0.0](https://semver.org/).

# Features

Jagged supports streaming encryption and decryption using standard recipient types.

- Encryption and decryption of [binary age files](https://github.com/C2SP/C2SP/blob/main/age.md#encrypted-file-format)
- Encryption and decryption of [armored age files](https://github.com/C2SP/C2SP/blob/main/age.md#ascii-armor)
- [X25519](https://github.com/C2SP/C2SP/blob/main/age.md#the-x25519-recipient-type) recipients and identities
- [scrypt](https://github.com/C2SP/C2SP/blob/main/age.md#the-scrypt-recipient-type) recipients and identities
- [ssh-rsa](https://github.com/FiloSottile/age/blob/main/README.md#ssh-keys) recipients and identities

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

The ssh-rsa type encrypts a File Key with RSA-OAEP.

- [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017) PKCS #1: RSA Cryptography Specifications Version 2.2

# Modules

Jagged consists of multiple modules supporting different aspects of the age encryption specification.

- jagged-api
- jagged-bech32
- jagged-framework
- jagged-scrypt
- jagged-ssh
- jagged-test
- jagged-x25519

## jagged-api

The
[jagged-api](https://javadoc.io/doc/com.exceptionfactory.jagged/jagged-api/latest/com/exceptionfactory/jagged/package-summary.html)
module contains the core public interfaces for encryption and decryption operations. The module
contains interfaces and classes in the `com.exceptionfactory.jagged` package, which provide integration and extension
points for other components.

The
[FileKey](https://javadoc.io/doc/com.exceptionfactory.jagged/jagged-api/latest/com/exceptionfactory/jagged/FileKey.html)
class implements
[java.crypto.SecretKey](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/javax/crypto/SecretKey.html)
and supports the primary contract for age identities and recipients.

The
[RecipientStanza](https://javadoc.io/doc/com.exceptionfactory.jagged/jagged-api/latest/com/exceptionfactory/jagged/RecipientStanza.html)
interface follows the pattern of the age [Stanza](https://pkg.go.dev/filippo.io/age#Stanza),
providing access to the Type, Arguments, and binary Body elements.

The
[RecipientStanzaReader](https://javadoc.io/doc/com.exceptionfactory.jagged/jagged-api/latest/com/exceptionfactory/jagged/RecipientStanzaReader.html)
interface serves as the age [Identity](https://pkg.go.dev/filippo.io/age#Identity) 
abstraction, responsible for reading `RecipientStanza` objects and return a decrypted `FileKey`.

The 
[RecipientStanzaWriter](https://javadoc.io/doc/com.exceptionfactory.jagged/jagged-api/latest/com/exceptionfactory/jagged/RecipientStanzaWriter.html)
interface follows the age [Recipient](https://pkg.go.dev/filippo.io/age#Recipient)
abstraction, responsible for wrapping a `FileKey` and returning a collection of `RecipientStanza` objects.

The
[EncryptingChannelFactory](https://javadoc.io/doc/com.exceptionfactory.jagged/jagged-api/latest/com/exceptionfactory/jagged/EncryptingChannelFactory.html)
interface wraps a provided
[WritableByteChannel](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/nio/channels/WritableByteChannel.html) and returns
a `WritableByteChannel` that supports streaming encryption to one or more recipients based on supplied
`RecipientStanzaWriter` instances.

The
[DecryptingChannelFactory](https://javadoc.io/doc/com.exceptionfactory.jagged/jagged-api/latest/com/exceptionfactory/jagged/DecryptingChannelFactory.html)
interface wraps a provided
[ReadableByteChannel](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/nio/channels/ReadableByteChannel.html) and returns
a `ReadableByteChannel` that supports streaming decryption for a matched identity based on supplied
`RecipientStanzaReader` instances.

## jagged-bech32

The 
[jagged-bech32](https://javadoc.io/doc/com.exceptionfactory.jagged/jagged-bech32/latest/com/exceptionfactory/jagged/bech32/package-summary.html)
module contains an implementation of the Bech32 encoding specification defined according to
[Bitcoin Improvement Proposal 0173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki). Bech32 encoding
supports a standard representation of X25519 private and public keys. The
[Bech32](https://javadoc.io/doc/com.exceptionfactory.jagged/jagged-bech32/latest/com/exceptionfactory/jagged/bech32/Bech32.html)
class follows the pattern of
[java.util.Base64](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/util/Base64.html) and encloses
[Bech32.Decoder](https://javadoc.io/doc/com.exceptionfactory.jagged/jagged-bech32/latest/com/exceptionfactory/jagged/bech32/Bech32.Decoder.html)
and
[Bech32.Encoder](https://javadoc.io/doc/com.exceptionfactory.jagged/jagged-bech32/latest/com/exceptionfactory/jagged/bech32/Bech32.Encoder.html)
interfaces. Bech32 encoding consists of a Human-Readable Part prefix, a separator, and data part that
ends with a checksum.

## jagged-framework

The 
[jagged-framework](https://javadoc.io/doc/com.exceptionfactory.jagged/jagged-framework/latest/index.html)
module includes shared components for common cryptographic operations.

The `stream` package includes the
[StandardDecryptingChannelFactory](https://javadoc.io/doc/com.exceptionfactory.jagged/jagged-framework/latest/com/exceptionfactory/jagged/framework/stream/StandardDecryptingChannelFactory.html)
and
[StandardEncryptingChannelFactory](https://javadoc.io/doc/com.exceptionfactory.jagged/jagged-framework/latest/com/exceptionfactory/jagged/framework/stream/StandardEncryptingChannelFactory.html)
classes,
which implement the corresponding public interfaces for streaming cipher operations.

The `armor` packaged includes the
[ArmoredDecryptingChannelFactory](https://javadoc.io/doc/com.exceptionfactory.jagged/jagged-framework/latest/com/exceptionfactory/jagged/framework/armor/ArmoredDecryptingChannelFactory.html)
and
[ArmoredEncryptingChannelFactory](https://javadoc.io/doc/com.exceptionfactory.jagged/jagged-framework/latest/com/exceptionfactory/jagged/framework/armor/ArmoredEncryptingChannelFactory.html)
classes,
supporting reading and writing ASCII armored files with standard PEM header and footer lines.

## jagged-scrypt

The
[jagged-scrypt](https://javadoc.io/doc/com.exceptionfactory.jagged/jagged-scrypt/latest/com/exceptionfactory/jagged/scrypt/package-summary.html)
module supports encryption and decryption using a passphrase and configurable work factor.

The
[ScryptRecipientStanzaReaderFactory](https://javadoc.io/doc/com.exceptionfactory.jagged/jagged-scrypt/latest/com/exceptionfactory/jagged/scrypt/ScryptRecipientStanzaReaderFactory.html)
creates instances of `RecipientStanzaReader` using a passphrase.

The
[ScryptRecipientStanzaWriterFactory](https://javadoc.io/doc/com.exceptionfactory.jagged/jagged-scrypt/latest/com/exceptionfactory/jagged/scrypt/ScryptRecipientStanzaWriterFactory.html)
creates instances of `RecipientStanzaWriter` using a passphrase and 
a work factor with a minimum value of 2 and a maximum value of 20.

The module includes a custom implementation of the scrypt key derivation function with predefined settings that
match age encryption scrypt recipient specifications.

## jagged-ssh

The `jagged-ssh` module supports encryption and decryption using public and private SSH key pairs. The SSH key pair
implementation is compatible with the [agessh](https://pkg.go.dev/filippo.io/age/agessh) package, which defines
recipient stanzas with an algorithm and an encoded fingerprint of the public key.

The `SshRsaRecipientStanzaReaderFactory` creates instances of `RecipientStanzaReader` using an RSA private key or an
[OpenSSH Version 1 Private Key](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key).

The `SshRsaRecipientStanzaWriterFactory` creates instances of `RecipientStanzaWriter` using an RSA public key.

The SSH RSA implementation uses Optimal Asymmetric Encryption Padding as defined in
[RFC 8017 Section 7.1](https://www.rfc-editor.org/rfc/rfc8017#section-7.1). Following the age implementation, RSA OAEP
cipher operations use `SHA-256` as the hash algorithm with the mask generation function.

## jagged-x25519

The
[jagged-x25519](https://javadoc.io/doc/com.exceptionfactory.jagged/jagged-x25519/latest/com/exceptionfactory/jagged/x25519/package-summary.html)
module supports encryption and decryption using public and private key pairs. Key generation and
key agreement functions use the Java Cryptography Architecture framework. Key encoding and decoding functions use the
`jagged-bech32` library.

The `X25519KeyFactory` class implements
[java.security.KeyFactory](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyFactory.html)
and supports translating an encoded X25519 private key to the corresponding X25519 public key. The `translateKey` method
accepts an instance of the
[javax.crypto.spec.SecretKeySpec](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/javax/crypto/spec/SecretKeySpec.html)
class. The `SecretKeySpec` must be constructed with the `key` byte array containing the encoded private key, and with
`X25519` set as the value of the `algorithm` argument.

The 
[X25519KeyPairGenerator](https://javadoc.io/doc/com.exceptionfactory.jagged/jagged-x25519/latest/com/exceptionfactory/jagged/x25519/X25519KeyPairGenerator.html)
class implements
[java.security.KeyPairGenerator](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyPairGenerator.html)
and returns public and private key pairs encoded using Bech32.

The
[X25519RecipientStanzaReaderFactory](https://javadoc.io/doc/com.exceptionfactory.jagged/jagged-x25519/latest/com/exceptionfactory/jagged/x25519/X25519RecipientStanzaReaderFactory.html)
creates instances of `RecipientStanzaReader` using a private key encoded using
Bech32. Encoded private keys begin with `AGE-SECRET-KEY-1` as the Bech32 Human-Readable Part and separator.

The
[X25519RecipientStanzaWriterFactory](https://javadoc.io/doc/com.exceptionfactory.jagged/jagged-x25519/latest/com/exceptionfactory/jagged/x25519/X25519RecipientStanzaWriterFactory.html)
creates instances of `RecipientStanzaWriter` using a public key encoded using
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

## Code Quality

Jagged uses the following build plugins and services to evaluate code quality:

- [Apache Maven Checkstyle Plugin](https://maven.apache.org/plugins/maven-checkstyle-plugin/)
- [Apache Maven PMD Plugin](https://maven.apache.org/plugins/maven-pmd-plugin/)
- [Codecov](https://about.codecov.io/)
- [GitHub CodeQL](https://codeql.github.com/)
- [JaCoCo Maven Plugin](https://www.jacoco.org/jacoco/trunk/doc/maven.html)
- [SpotBugs Maven Plugin](https://spotbugs.github.io/spotbugs-maven-plugin/)

# Integrating

Jagged supports streaming encryption and decryption using
[Java NIO](https://docs.oracle.com/en/java/javase/17/core/java-nio.html) buffers and channels. Java NIO supports
efficient file read and write operations, minimizing memory impact using instances of
[java.nio.ByteBuffer](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/nio/ByteBuffer.html) to process
bytes. The
[java.nio.channel.Channels](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/nio/channels/Channels.html)
class provides several methods supporting interoperation with Java IO streams.

The [X25519](https://github.com/C2SP/C2SP/blob/main/age.md#the-x25519-recipient-type) recipient type with
[binary](https://github.com/C2SP/C2SP/blob/main/age.md#encrypted-file-format) formatting provides the
optimal solution for integrating age encryption. X25519 public and private keys encoded using Bech32 avoid the cost of
password-based key derivation, and binary formatting for encrypted files does not have the overhead of armored Base64
encoding and decoding.

## X25519 Key Pair Generation

Jagged supports public and private keys produced using the [age-keygen](https://filippo.io/age/age-keygen.1) command and
also provides key pair generation using the
[X25519KeyPairGenerator](https://javadoc.io/doc/com.exceptionfactory.jagged/jagged-x25519/latest/com/exceptionfactory/jagged/x25519/X25519KeyPairGenerator.html)
class. The class implements
[KeyPairGenerator](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyPairGenerator.html) and
supports standard methods for generating
[KeyPair](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyPair.html) instances. Both
[PublicKey](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/PublicKey.html) and
[PrivateKey](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/PrivateKey.html) implementations
return Bech32 encoded representations following the age specification.

```
final KeyPairGenerator keyPairGenerator = new X25519KeyPairGenerator();
final KeyPair keyPair = keyPairGenerator.generateKeyPair();
final PublicKey publicKey = keyPair.getPublic();
System.out.printf("Public key: %s", publicKey);
```

## Binary File Encryption with X25519

Encryption operations require one or more X25519 public keys. Jagged provides the 
[X25519RecipientStanzaWriterFactory](https://javadoc.io/doc/com.exceptionfactory.jagged/jagged-x25519/latest/com/exceptionfactory/jagged/x25519/X25519RecipientStanzaWriterFactory.html)
class for creating instances of
[RecpientStanzaWriter](https://javadoc.io/doc/com.exceptionfactory.jagged/jagged-api/latest/com/exceptionfactory/jagged/RecipientStanzaWriter.html)
to support encryption operations. The factory class accepts a
standard Java String containing a Bech32 encoded public key starting with `age1` and also supports other implementations
of [CharSequence](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/lang/CharSequence.html) to provide
more control over encoded keys.

The
[java.nio.file.Path](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/nio/file/Path.html) class
represents file locations and enables creation of
[java.nio.Channel](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/nio/channels/Channel.html) objects
for reading input files and writing encrypted output files.

```
final CharSequence publicKey = getPublicKey();
final RecipientStanzaWriter stanzaWriter = X25519RecipientStanzaWriterFactory.newRecipientStanzaWriter(publicKey);
final EncryptingChannelFactory channelFactory = new StandardEncryptingChannelFactory();

final Path inputPath = getInputPath();
final Path outputPath = getOutputPath();
try (
    final ReadableByteChannel inputChannel = Files.newByteChannel(inputPath);
    final WritableByteChannel encryptingChannel = channelFactory.newEncryptingChannel(
        Files.newByteChannel(outputPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE),
        Collections.singletonList(stanzaWriter)
    );
) {
    copy(inputChannel, encryptingChannel);
}
```

## Binary File Decryption with X25519

Decryption operations require a private key corresponding to a recipient from the age file header. Jagged provides the
[X25519RecipientStanzaReaderFactory](https://javadoc.io/doc/com.exceptionfactory.jagged/jagged-x25519/latest/com/exceptionfactory/jagged/x25519/X25519RecipientStanzaReaderFactory.html)
class for creating instances of
[RecipientStanzaReader](https://javadoc.io/doc/com.exceptionfactory.jagged/jagged-api/latest/com/exceptionfactory/jagged/RecipientStanzaReader.html)
to support decryption
operations. The factory class accepts a Bech32 encoded private key starting with `AGE-SECRET-KEY-1` represented as a
Java String or sequence of characters.

```
final CharSequence privateKey = getPrivateKey();
final RecipientStanzaReader stanzaReader = X25519RecipientStanzaReaderFactory.newRecipientStanzaReader(privateKey);
final DecryptingChannelFactory channelFactory = new StandardDecryptingChannelFactory();

final Path inputPath = getInputPath();
final Path outputPath = getOutputPath();
try (
    final WritableByteChannel outputChannel = Files.newByteChannel(
        outputPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE
    );
    final ReadableByteChannel decryptingChannel = channelFactory.newDecryptingChannel(
        Files.newByteChannel(inputPath),
        Collections.singletonList(stanzaReader)
    );
) {
    copy(decryptingChannel, outputChannel);
}
```

## Channel Processing

The age specification defines the encrypted [binary payload](https://github.com/C2SP/C2SP/blob/main/age.md#payload) as
consisting of chunks containing 64 kilobytes. Allocating a `ByteBuffer` with a capacity of `65536` enables integrating
components to process chunks with an optimal number of method invocations. Transferring bytes from a
[ReadableByteChannel](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/nio/channels/ReadableByteChannel.html)
to a
[WritableByteChannel](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/nio/channels/WritableByteChannel.html)
requires iterative processing to avoid partial reads or writes.

```
void copy(
    final ReadableByteChannel inputChannel,
    final WritableByteChannel outputChannel
) throws IOException {
    final ByteBuffer buffer = ByteBuffer.allocate(65536);
    while (inputChannel.read(buffer) != -1) {
        buffer.flip();
        while (buffer.hasRemaining()) {
            outputChannel.write(buffer);
        }
        buffer.clear();
    }
}
```

# Licensing

Jagged is released under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).
