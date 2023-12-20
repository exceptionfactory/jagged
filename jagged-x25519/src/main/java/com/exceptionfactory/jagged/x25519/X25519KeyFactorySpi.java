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

import com.exceptionfactory.jagged.bech32.Bech32;
import com.exceptionfactory.jagged.bech32.Bech32Address;
import com.exceptionfactory.jagged.framework.crypto.SharedSecretKey;

import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Objects;

/**
 * X25519 Key Factory implementation supporting Public Key generation from an encoded Private Key
 */
class X25519KeyFactorySpi extends KeyFactorySpi {
    private static final Charset ENCODING_CHARACTER_SET = StandardCharsets.US_ASCII;

    private static final BasePointPublicKey BASE_POINT_PUBLIC_KEY = new BasePointPublicKey();

    private static final Bech32.Encoder ENCODER = Bech32.getEncoder();

    private static final Bech32.Decoder DECODER = Bech32.getDecoder();

    private final KeyAgreementFactory keyAgreementFactory;

    private final RecipientKeyFactory recipientKeyFactory;

    /**
     * X25519 Key Factory constructor with required properties configured using available Security Providers
     *
     * @param keyAgreementFactory Key Agreement Factory for X25519
     * @param recipientKeyFactory Recipient Key Factory for X25519
     */
    X25519KeyFactorySpi(final KeyAgreementFactory keyAgreementFactory, final RecipientKeyFactory recipientKeyFactory) {
        this.keyAgreementFactory = Objects.requireNonNull(keyAgreementFactory, "Key Agreement Factory required");
        this.recipientKeyFactory = Objects.requireNonNull(recipientKeyFactory, "Recipient Key Factory required");
    }

    /**
     * Generate Public Key not supported
     *
     * @param keySpec Key Specification
     * @return Public Key
     * @throws InvalidKeySpecException Thrown on method invocation
     */
    @Override
    protected PublicKey engineGeneratePublic(final KeySpec keySpec) throws InvalidKeySpecException {
        throw new InvalidKeySpecException("Generate Public Key not supported");
    }

    /**
     * Generate Private Key not supported
     *
     * @param keySpec Key Specification
     * @return Private Key
     * @throws InvalidKeySpecException Thrown on method invocation
     */
    @Override
    protected PrivateKey engineGeneratePrivate(final KeySpec keySpec) throws InvalidKeySpecException {
        throw new InvalidKeySpecException("Generate Private Key not supported");
    }

    /**
     * Get Key Specification not supported
     *
     * @param key Key
     * @param keySpec Key Specification class to be returned
     * @return Key Specification
     * @param <T> Key Specification Type
     * @throws InvalidKeySpecException Thrown on method invocation
     */
    @Override
    protected <T extends KeySpec> T engineGetKeySpec(final Key key, final Class<T> keySpec) throws InvalidKeySpecException {
        throw new InvalidKeySpecException("Get Key Specification not supported");
    }

    /**
     * Translate Secret Key Specification containing encoded X25519 Private Key to X25519 Public Key
     *
     * @param key Key supporting instances of Secret Key Specification
     * @return X25519 Public Key derived from X25519 Private Key
     * @throws InvalidKeyException Thrown on unsupported Key classes or invalid encoding
     */
    @Override
    protected Key engineTranslateKey(final Key key) throws InvalidKeyException {
        Objects.requireNonNull(key, "Key required");
        if (key instanceof SecretKeySpec) {
            final SecretKeySpec secretKeySpec = (SecretKeySpec) key;
            try {
                return getPublicKey(secretKeySpec);
            } catch (final GeneralSecurityException e) {
                throw new InvalidKeyException("Secret Key conversion failed", e);
            }
        } else {
            final String message = String.format("Key not supported [%s]", key.getClass());
            throw new InvalidKeyException(message);
        }
    }

    private PublicKey getPublicKey(final SecretKeySpec secretKeySpec) throws GeneralSecurityException {
        final ByteBuffer encoded = ByteBuffer.wrap(secretKeySpec.getEncoded());
        final CharBuffer characters = ENCODING_CHARACTER_SET.decode(encoded);
        final Bech32Address address = DECODER.decode(characters);

        final CharSequence humanReadablePart = address.getHumanReadablePart();
        if (IdentityIndicator.PRIVATE_KEY_HUMAN_READABLE_PART.getIndicator().contentEquals(humanReadablePart)) {
            final byte[] privateKeyEncoded = address.getData();
            final SharedSecretKey sharedSecretKey = getSharedSecretKey(privateKeyEncoded);
            return getPublicKey(sharedSecretKey);
        } else {
            final String message = String.format("Private Key Human-Readable Part not matched [%s]", humanReadablePart);
            throw new InvalidKeySpecException(message);
        }
    }

    private SharedSecretKey getSharedSecretKey(final byte[] privateKeyEncoded) throws GeneralSecurityException {
        final PrivateKey privateKey = recipientKeyFactory.getPrivateKey(privateKeyEncoded);
        final SharedSecretKeyProducer sharedSecretKeyProducer = new X25519SharedSecretKeyProducer(privateKey, keyAgreementFactory);
        final PublicKey basePointPublicKey = recipientKeyFactory.getPublicKey(BASE_POINT_PUBLIC_KEY.getEncoded());
        return sharedSecretKeyProducer.getSharedSecretKey(basePointPublicKey);
    }

    private X25519PublicKey getPublicKey(final SharedSecretKey sharedSecretKey) {
        final byte[] coordinateEncoded = sharedSecretKey.getEncoded();
        final CharSequence publicKeyEncoded = ENCODER.encode(RecipientIndicator.PUBLIC_KEY_HUMAN_READABLE_PART.getIndicator(), coordinateEncoded);
        final byte[] encoded = getEncoded(publicKeyEncoded);
        return new X25519PublicKey(encoded);
    }

    private byte[] getEncoded(final CharSequence keyEncoded) {
        final CharBuffer keyBuffer = CharBuffer.wrap(keyEncoded);
        final ByteBuffer buffer = ENCODING_CHARACTER_SET.encode(keyBuffer);
        return buffer.array();
    }
}
