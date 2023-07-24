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
package com.exceptionfactory.jagged.x25519;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Objects;

/**
 * Standard implementation of X25519 Recipient Key Factory using ASN.1 with DER for Java Cryptography
 */
class StandardRecipientKeyFactory implements RecipientKeyFactory {
    private static final int COORDINATE_LENGTH = RecipientKeyType.X25519.getKeyLength();

    /** PKCS8 Private Key specification encoded length in bytes containing 32 byte key plus DER encoded version and algorithm */
    private static final int PRIVATE_KEY_SPECIFICATION_ENCODED_LENGTH = 48;

    /** PKCS8 Private Key DER encoded length in bytes containing 32 byte key plus version and algorithm identifier */
    private static final int PRIVATE_KEY_DER_ENCODED_LENGTH = 46;

    private static final int PRIVATE_KEY_DER_ENCODED_LENGTH_INDEX = 1;

    private static final int PRIVATE_KEY_DER_HEADER_LENGTH = 16;

    private final int publicKeyEncodedLength;

    private final byte[] publicKeyHeader;

    private final byte[] privateKeyHeader;

    /**
     * Standard Recipient Key Factory constructor generates a random Key Pair to derive Public and Private Key Headers
     * based on the current Java Security Provider
     *
     * @throws GeneralSecurityException Thrown on failures generating a random Key Pair
     */
    StandardRecipientKeyFactory() throws GeneralSecurityException {
        final KeyPairGenerator keyPairGenerator = getKeyPairGenerator();
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
     * Get Public Key from encoded binary
     *
     * @param publicKeyEncoded Encoded curve coordinate public key of 32 bytes
     * @return Public Key
     * @throws GeneralSecurityException Thrown on key processing failures
     */
    @Override
    public PublicKey getPublicKey(final byte[] publicKeyEncoded) throws GeneralSecurityException {
        Objects.requireNonNull(publicKeyEncoded, "Public Key required");
        final int encodedLength = publicKeyEncoded.length;
        if (COORDINATE_LENGTH == encodedLength) {
            final X509EncodedKeySpec publicKeySpec = getPublicKeySpec(publicKeyEncoded);
            final KeyFactory keyFactory = getKeyFactory();
            return keyFactory.generatePublic(publicKeySpec);
        } else {
            final String message = String.format("Public key length [%d] not required length [%d]", encodedLength, COORDINATE_LENGTH);
            throw new InvalidKeyException(message);
        }
    }

    /**
     * Get Private Key from encoded binary
     *
     * @param privateKeyEncoded Encoded curve coordinate private key of 32 bytes
     * @return Private Key
     * @throws GeneralSecurityException Thrown on key processing failures
     */
    @Override
    public PrivateKey getPrivateKey(final byte[] privateKeyEncoded) throws GeneralSecurityException {
        Objects.requireNonNull(privateKeyEncoded, "Private Key required");
        final int encodedLength = privateKeyEncoded.length;
        if (COORDINATE_LENGTH == encodedLength) {
            final PKCS8EncodedKeySpec privateKeySpec = getPrivateKeySpec(privateKeyEncoded);
            final KeyFactory keyFactory = getKeyFactory();
            return keyFactory.generatePrivate(privateKeySpec);
        } else {
            final String message = String.format("Private key length [%d] not required length [%d]", encodedLength, COORDINATE_LENGTH);
            throw new InvalidKeyException(message);
        }
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

    private KeyFactory getKeyFactory() throws NoSuchAlgorithmException {
        return KeyFactory.getInstance(RecipientIndicator.KEY_ALGORITHM.getIndicator());
    }

    private KeyPairGenerator getKeyPairGenerator() throws NoSuchAlgorithmException {
        return KeyPairGenerator.getInstance(RecipientIndicator.KEY_ALGORITHM.getIndicator());
    }

    private static byte[] getPrivateKeyHeader(final PrivateKey privateKey) {
        final byte[] privateKeyEncoded = privateKey.getEncoded();
        final byte[] privateKeyHeader = Arrays.copyOfRange(privateKeyEncoded, 0, PRIVATE_KEY_DER_HEADER_LENGTH);
        // Set DER encoded length to override potential longer values from other providers
        privateKeyHeader[PRIVATE_KEY_DER_ENCODED_LENGTH_INDEX] = PRIVATE_KEY_DER_ENCODED_LENGTH;
        return privateKeyHeader;
    }
}
