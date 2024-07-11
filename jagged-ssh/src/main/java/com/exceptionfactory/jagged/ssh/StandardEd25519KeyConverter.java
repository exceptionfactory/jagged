/*
 * Copyright 2023 Jagged Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.exceptionfactory.jagged.ssh;

import com.exceptionfactory.jagged.framework.crypto.SharedSecretKey;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Objects;

/**
 * Standard implementation of Ed25519 key converter using Java Cryptography Architecture interfaces and BigInteger processing
 */
final class StandardEd25519KeyConverter implements Ed25519KeyConverter {
    /** Curve25519 coordinate length in bytes */
    private static final int COORDINATE_LENGTH = 32;

    /** PKCS8 Private Key specification encoded length in bytes containing 32 byte key plus DER encoded version and algorithm */
    private static final int PRIVATE_KEY_SPECIFICATION_ENCODED_LENGTH = 48;

    /** PKCS8 Private Key DER encoded length in bytes containing 32 byte key plus version and algorithm identifier */
    private static final int PRIVATE_KEY_DER_ENCODED_LENGTH = 46;

    private static final int PRIVATE_KEY_DER_ENCODED_LENGTH_INDEX = 1;

    private static final int PRIVATE_KEY_DER_HEADER_LENGTH = 16;

    private static final String DIGEST_ALGORITHM = "SHA-512";

    private static final int CURVE_25519_EXPONENT = 255;

    private static final BigInteger CURVE_25519_PRIME = BigInteger.valueOf(2).pow(CURVE_25519_EXPONENT).subtract(BigInteger.valueOf(19));

    private static final byte SIGNIFICANT_BIT_MASK = 0b01111111;

    private final int publicKeyEncodedLength;

    private final byte[] publicKeyHeader;

    private final byte[] privateKeyHeader;

    private final KeyFactory keyFactory;

    StandardEd25519KeyConverter(final X25519KeyPairGeneratorFactory keyPairGeneratorFactory) throws NoSuchAlgorithmException {
        final KeyPairGenerator keyPairGenerator = keyPairGeneratorFactory.getKeyPairGenerator();
        final Provider provider = keyPairGenerator.getProvider();
        keyFactory = KeyFactory.getInstance(EllipticCurveKeyType.X25519.getAlgorithm(), provider);
        final KeyPair keyPair = keyPairGenerator.generateKeyPair();

        final PrivateKey privateKey = keyPair.getPrivate();
        privateKeyHeader = getPrivateKeyHeader(privateKey);

        final PublicKey publicKey = keyPair.getPublic();
        final byte[] publicKeyEncoded = publicKey.getEncoded();
        publicKeyEncodedLength = publicKeyEncoded.length;
        final int publicKeyHeaderLength = publicKeyEncodedLength - COORDINATE_LENGTH;
        publicKeyHeader = Arrays.copyOfRange(publicKeyEncoded, 0, publicKeyHeaderLength);
    }

    /**
     * Get X25519 Private Key from first 32 bytes of SHA-512 hash of Ed25519 Private Key
     *
     * @param ed25519PrivateKey Ed25519 private key
     * @return X25519 Private Key
     * @throws GeneralSecurityException Thrown on failure to generate private key
     */
    @Override
    public PrivateKey getPrivateKey(final Ed25519PrivateKey ed25519PrivateKey) throws GeneralSecurityException {
        Objects.requireNonNull(ed25519PrivateKey, "Ed25519 Private Key required");

        final MessageDigest messageDigest = MessageDigest.getInstance(DIGEST_ALGORITHM);
        final byte[] encoded = ed25519PrivateKey.getEncoded();
        final byte[] digested = messageDigest.digest(encoded);
        final byte[] converted = new byte[COORDINATE_LENGTH];
        System.arraycopy(digested, 0, converted, 0, COORDINATE_LENGTH);

        final PKCS8EncodedKeySpec privateKeySpec = getPrivateKeySpec(converted);
        return keyFactory.generatePrivate(privateKeySpec);
    }

    /**
     * Get X25519 Private Key from SSH Ed25519 derived key
     *
     * @param derivedKey SSH Ed25519 derived key
     * @return X25519 Private Key
     * @throws GeneralSecurityException Thrown on failure to convert private key
     */
    @Override
    public PrivateKey getPrivateKey(final SshEd25519DerivedKey derivedKey) throws GeneralSecurityException {
        final byte[] encoded = Objects.requireNonNull(derivedKey, "Derived Key required").getEncoded();
        final PKCS8EncodedKeySpec privateKeySpec = getPrivateKeySpec(encoded);
        return keyFactory.generatePrivate(privateKeySpec);
    }

    /**
     * Get X25519 Public Key from Ed25519 Public Key public computed using equivalence mapping described in RFC 7748 Section 4.1
     *
     * @param ed25519PublicKey Ed25519 public key
     * @return X25519 Public Key
     * @throws GeneralSecurityException Thrown on failure to convert public key
     */
    @Override
    public PublicKey getPublicKey(final Ed25519PublicKey ed25519PublicKey) throws GeneralSecurityException {
        final byte[] encoded = Objects.requireNonNull(ed25519PublicKey, "Ed25519 Public Key required").getEncoded();
        final byte[] montgomeryCoordinate = getMontgomeryCoordinate(encoded);

        final X509EncodedKeySpec publicKeySpec = getPublicKeySpec(montgomeryCoordinate);
        return keyFactory.generatePublic(publicKeySpec);
    }

    /**
     * Get X25519 Public Key from shared secret encoded binary key
     *
     * @param sharedSecretKey Computed shared secret key
     * @return X25519 Public Key
     * @throws GeneralSecurityException Thrown on key processing failures
     */
    @Override
    public PublicKey getPublicKey(final SharedSecretKey sharedSecretKey) throws GeneralSecurityException {
        Objects.requireNonNull(sharedSecretKey, "Key required");
        final byte[] encoded = sharedSecretKey.getEncoded();
        final X509EncodedKeySpec publicKeySpec = getPublicKeySpec(encoded);
        return keyFactory.generatePublic(publicKeySpec);
    }

    private PKCS8EncodedKeySpec getPrivateKeySpec(final byte[] privateKeyEncoded) {
        final byte[] keySpec = new byte[PRIVATE_KEY_SPECIFICATION_ENCODED_LENGTH];
        System.arraycopy(privateKeyHeader, 0, keySpec, 0, privateKeyHeader.length);
        System.arraycopy(privateKeyEncoded, 0, keySpec, privateKeyHeader.length, privateKeyEncoded.length);
        return new PKCS8EncodedKeySpec(keySpec);
    }

    private X509EncodedKeySpec getPublicKeySpec(final byte[] publicKeyEncoded) {
        final byte[] keySpec = new byte[publicKeyEncodedLength];
        System.arraycopy(publicKeyHeader, 0, keySpec, 0, publicKeyHeader.length);
        System.arraycopy(publicKeyEncoded, 0, keySpec, publicKeyHeader.length, publicKeyEncoded.length);
        return new X509EncodedKeySpec(keySpec);
    }

    private static byte[] getPrivateKeyHeader(final PrivateKey privateKey) {
        final byte[] privateKeyEncoded = privateKey.getEncoded();
        final byte[] privateKeyHeader = Arrays.copyOfRange(privateKeyEncoded, 0, PRIVATE_KEY_DER_HEADER_LENGTH);
        // Set DER encoded length to override potential longer values from other providers
        privateKeyHeader[PRIVATE_KEY_DER_ENCODED_LENGTH_INDEX] = PRIVATE_KEY_DER_ENCODED_LENGTH;
        return privateKeyHeader;
    }

    private byte[] getMontgomeryCoordinate(final byte[] edwardsCoordinateLittleEndian) {
        final byte[] reversed = getReversed(edwardsCoordinateLittleEndian);
        reversed[0] &= SIGNIFICANT_BIT_MASK;

        final BigInteger secondEdwardsCoordinate = new BigInteger(reversed);
        final BigInteger denominator = BigInteger.ONE.subtract(secondEdwardsCoordinate);
        final BigInteger inverted = denominator.modInverse(CURVE_25519_PRIME);

        final BigInteger numerator = BigInteger.ONE.add(secondEdwardsCoordinate);
        final BigInteger firstEdwardsCoordinate = numerator.multiply(inverted);
        final BigInteger montgomeryCoordinate = firstEdwardsCoordinate.mod(CURVE_25519_PRIME);

        final byte[] montgomeryCoordinateEncoded = montgomeryCoordinate.toByteArray();
        return getReversed(montgomeryCoordinateEncoded);
    }

    private byte[] getReversed(final byte[] encoded) {
        final byte[] reversed = new byte[encoded.length];

        int i = encoded.length - 1;
        for (final byte encodedItem : encoded) {
            reversed[i] = encodedItem;
            i--;
        }

        return reversed;
    }
}
