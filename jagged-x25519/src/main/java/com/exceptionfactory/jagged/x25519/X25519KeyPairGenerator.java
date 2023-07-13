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

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * X25519 Key Pair Generator produces Public and Private Keys encoded using Bech32 for use with age encryption
 */
public class X25519KeyPairGenerator extends KeyPairGenerator {
    private static final Charset ENCODING_CHARACTER_SET = StandardCharsets.US_ASCII;

    private static final String ALGORITHM = RecipientIndicator.KEY_ALGORITHM.getIndicator();

    private static final Bech32.Encoder ENCODER = Bech32.getEncoder();

    private static final int ENCODED_COORDINATE_LENGTH = 32;

    private final KeyPairGenerator keyPairGenerator;

    /**
     * X25519 Key Pair Generator constructor creates a Key Pair Generator using available Security Providers
     *
     * @throws NoSuchAlgorithmException Thrown on KeyPairGenerator.getInstance() failures
     */
    public X25519KeyPairGenerator() throws NoSuchAlgorithmException {
        super(ALGORITHM);
        this.keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
    }

    /**
     * Generate Key Pair with encoded X25519 Public Key and Private Key
     *
     * @return Pair of X25519 Public Key and Private Key
     */
    @Override
    public KeyPair generateKeyPair() {
        final KeyPair keyPair = keyPairGenerator.generateKeyPair();
        final X25519PublicKey publicKey = getPublicKey(keyPair.getPublic());
        final X25519PrivateKey privateKey = getPrivateKey(keyPair.getPrivate());
        return new KeyPair(publicKey, privateKey);
    }

    private X25519PublicKey getPublicKey(final PublicKey publicKey) {
        final byte[] coordinate = getCoordinate(publicKey);
        final CharSequence publicKeyEncoded = ENCODER.encode(RecipientIndicator.PUBLIC_KEY_HUMAN_READABLE_PART.getIndicator(), coordinate);
        final byte[] encoded = getEncoded(publicKeyEncoded);
        return new X25519PublicKey(encoded);
    }

    private X25519PrivateKey getPrivateKey(final PrivateKey privateKey) {
        final byte[] coordinate = getCoordinate(privateKey);
        final CharSequence privateKeyEncoded = ENCODER.encode(IdentityIndicator.PRIVATE_KEY_HUMAN_READABLE_PART.getIndicator(), coordinate);
        final byte[] encoded = getEncoded(privateKeyEncoded);
        return new X25519PrivateKey(encoded);
    }

    private byte[] getEncoded(final CharSequence keyEncoded) {
        final CharBuffer keyBuffer = CharBuffer.wrap(keyEncoded);
        final ByteBuffer buffer = ENCODING_CHARACTER_SET.encode(keyBuffer);
        return buffer.array();
    }

    private byte[] getCoordinate(final Key key) {
        final byte[] encoded = key.getEncoded();
        final int coordinateStartIndex = encoded.length - ENCODED_COORDINATE_LENGTH;
        return Arrays.copyOfRange(encoded, coordinateStartIndex, encoded.length);
    }
}
