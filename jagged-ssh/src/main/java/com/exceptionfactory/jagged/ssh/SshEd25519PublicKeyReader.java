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

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * SSH Ed25519 Public Key Reader implementation based on ssh-ed25519 format described in RFC 8709 Section 4
 */
class SshEd25519PublicKeyReader extends SshPublicKeyReader<Ed25519PublicKey> {
    private static final int ENCODED_LENGTH = 68;

    private static final String ALGORITHM_FORMAT = SshEd25519RecipientIndicator.STANZA_TYPE.getIndicator();

    private static final byte[] ALGORITHM = ALGORITHM_FORMAT.getBytes(StandardCharsets.UTF_8);

    private static final byte SPACE_SEPARATOR = 32;

    private static final Base64.Decoder DECODER = Base64.getDecoder();

    /**
     * Read Public Key
     *
     * @param inputBuffer Input Buffer to be read
     * @return Ed25519 Public Key
     * @throws GeneralSecurityException Thrown on failures to parse input buffer
     */
    @Override
    public Ed25519PublicKey read(final ByteBuffer inputBuffer) throws GeneralSecurityException {
        Objects.requireNonNull(inputBuffer, "Input Buffer required");

        final byte[] algorithm = new byte[ALGORITHM.length];
        inputBuffer.get(algorithm);

        final Ed25519PublicKey publicKey;

        if (Arrays.equals(ALGORITHM, algorithm)) {
            final byte separator = inputBuffer.get();
            if (SPACE_SEPARATOR == separator) {
                publicKey = readEncodedPublicKey(inputBuffer);
            } else {
                throw new InvalidKeyException("Algorithm format space separator not found");
            }
        } else {
            throw new InvalidKeyException(String.format("Public key algorithm format [%s] not found", ALGORITHM_FORMAT));
        }

        return publicKey;
    }

    private Ed25519PublicKey readEncodedPublicKey(final ByteBuffer inputBuffer) throws InvalidKeyException {
        final Ed25519PublicKey publicKey;

        if (inputBuffer.remaining() >= ENCODED_LENGTH) {
            final byte[] encoded = new byte[ENCODED_LENGTH];
            inputBuffer.get(encoded);

            final byte[] decoded = DECODER.decode(encoded);
            final ByteBuffer decodedBuffer = ByteBuffer.wrap(decoded);

            final byte[] algorithm = readBlock(decodedBuffer);
            if (Arrays.equals(ALGORITHM, algorithm)) {
                publicKey = readPublicKey(decodedBuffer);
            } else {
                throw new InvalidKeyException(String.format("Encoded key algorithm [%s] not found", ALGORITHM_FORMAT));
            }
        } else {
            final int remaining = inputBuffer.remaining();
            final String message = String.format("Encoded public key length [%d] less than required [%d]", remaining, ENCODED_LENGTH);
            throw new InvalidKeyException(message);
        }

        return publicKey;
    }

    private Ed25519PublicKey readPublicKey(final ByteBuffer decodedBuffer) throws InvalidKeyException {
        final byte[] block = readBlock(decodedBuffer);
        if (EllipticCurveKeyType.ED25519.getKeyLength() == block.length) {
            return new Ed25519PublicKey(block);
        } else {
            final String message = String.format("Public key length [%d] not expected [%d]", block.length, EllipticCurveKeyType.ED25519.getKeyLength());
            throw new InvalidKeyException(message);
        }
    }
}
