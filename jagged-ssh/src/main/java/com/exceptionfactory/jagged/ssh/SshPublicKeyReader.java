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
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * SSH Public Key Reader with shared methods
 *
 * @param <T> Public Key Type
 */
abstract class SshPublicKeyReader<T extends PublicKey> implements PublicKeyReader<T> {
    private static final int INTEGER_LENGTH = 4;

    private static final byte SPACE_SEPARATOR = 32;

    private static final Base64.Decoder DECODER = Base64.getDecoder();

    private final String keyAlgorithm;

    private final byte[] keyAlgorithmBinary;

    /**
     * SSH Public Key Reader constructor with required key algorithm
     *
     * @param keyAlgorithm Public key algorithm
     */
    SshPublicKeyReader(final String keyAlgorithm) {
        this.keyAlgorithm = Objects.requireNonNull(keyAlgorithm, "Algorithm required");
        this.keyAlgorithmBinary = keyAlgorithm.getBytes(StandardCharsets.US_ASCII);
    }

    /**
     * Read Public Key
     *
     * @param inputBuffer Input Buffer to be read
     * @return RSA Public Key
     * @throws GeneralSecurityException Thrown on failures to parse input buffer
     */
    @Override
    public T read(final ByteBuffer inputBuffer) throws GeneralSecurityException {
        Objects.requireNonNull(inputBuffer, "Input Buffer required");

        final T publicKey;

        final byte[] algorithm = new byte[keyAlgorithmBinary.length];
        inputBuffer.get(algorithm);

        if (Arrays.equals(keyAlgorithmBinary, algorithm)) {
            final byte separator = inputBuffer.get();
            if (SPACE_SEPARATOR == separator) {
                publicKey = readEncodedPublicKey(inputBuffer);
            } else {
                throw new InvalidKeyException("Algorithm format space separator not found");
            }
        } else {
            throw new InvalidKeyException(String.format("Public key algorithm format [%s] not found", keyAlgorithm));
        }

        return publicKey;
    }

    /**
     * Read Public Key from decoded buffer
     *
     * @param decodedBuffer Buffer of bytes decoded from Base64 public key
     * @return Public Key
     * @throws GeneralSecurityException Thrown when the decoded buffer does not contain valid key information
     */
    protected abstract T readPublicKey(ByteBuffer decodedBuffer) throws GeneralSecurityException;

    /**
     * Read length-delimited array of bytes
     *
     * @param buffer Byte buffer to be read
     * @return Byte array read
     * @throws InvalidKeyException Thrown on invalid number of bytes indicated to be read
     */
    protected byte[] readBlock(final ByteBuffer buffer) throws InvalidKeyException {
        if (buffer.remaining() < INTEGER_LENGTH) {
            throw new InvalidKeyException(String.format("Public Key buffer size [%d] less than required", buffer.remaining()));
        }

        final int length = buffer.getInt();
        if (length > buffer.remaining()) {
            throw new InvalidKeyException(String.format("Public Key block length [%d] not valid", length));
        }

        final byte[] block = new byte[length];
        buffer.get(block);
        return block;
    }

    private T readEncodedPublicKey(final ByteBuffer inputBuffer) throws GeneralSecurityException {
        final T publicKey;

        final byte[] encoded = readEncodedBytes(inputBuffer);
        final byte[] decoded = DECODER.decode(encoded);
        final ByteBuffer decodedBuffer = ByteBuffer.wrap(decoded);

        final byte[] algorithm = readBlock(decodedBuffer);
        if (Arrays.equals(keyAlgorithmBinary, algorithm)) {
            publicKey = readPublicKey(decodedBuffer);
        } else {
            throw new InvalidKeyException(String.format("Encoded key algorithm [%s] not found", keyAlgorithm));
        }

        return publicKey;
    }

    private byte[] readEncodedBytes(final ByteBuffer inputBuffer) {
        final int startPosition = inputBuffer.position();

        int endPosition = startPosition;
        while (inputBuffer.hasRemaining()) {
            final byte character = inputBuffer.get();
            if (SPACE_SEPARATOR == character) {
                break;
            }
            endPosition = inputBuffer.position();
        }

        final int length = endPosition - startPosition;
        final byte[] encoded = new byte[length];
        inputBuffer.position(startPosition);
        inputBuffer.get(encoded);
        return encoded;
    }
}
