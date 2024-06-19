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

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;

/**
 * OpenSSH Key Version 1 base class for reading ByteBuffers
 */
abstract class OpenSshKeyByteBufferReader implements KeyPairReader {
    private static final int INTEGER_SIZE = 4;

    /**
     * Read US-ASCII String from length-delimited bytes
     *
     * @param buffer Byte buffer to be read
     * @return US-ASCII String
     * @throws InvalidKeyException Thrown on invalid number of bytes indicated to be read
     */
    protected String readString(final ByteBuffer buffer) throws InvalidKeyException {
        final byte[] block = readBlock(buffer);
        return new String(block, StandardCharsets.US_ASCII);
    }

    /**
     * Read Big Integer from length-delimited bytes
     *
     * @param buffer Byte buffer to be read
     * @return Big Integer read from byte array
     * @throws InvalidKeyException Thrown on invalid number of bytes indicated to be read
     */
    protected BigInteger readBigInteger(final ByteBuffer buffer) throws InvalidKeyException {
        final byte[] block = readBlock(buffer);
        return new BigInteger(block);
    }

    /**
     * Read length-delimited array of bytes
     *
     * @param buffer Byte buffer to be read
     * @return Byte array read
     * @throws InvalidKeyException Thrown on invalid number of bytes indicated to be read
     */
    protected byte[] readBlock(final ByteBuffer buffer) throws InvalidKeyException {
        final int length = readInteger(buffer);
        if (length > buffer.remaining()) {
            throw new InvalidKeyException(String.format("OpenSSH Key block length [%d] not valid", length));
        }

        final byte[] block = new byte[length];
        buffer.get(block);
        return block;
    }

    /**
     * Read integer from four bytes of buffer
     *
     * @param buffer Byte buffer to be read
     * @return Integer read from four bytes of buffer
     * @throws InvalidKeyException Thrown when buffer contains less than the number of bytes required to read an integer
     */
    protected int readInteger(final ByteBuffer buffer) throws InvalidKeyException {
        final int integer;
        if (buffer.remaining() >= INTEGER_SIZE) {
            integer = buffer.getInt();
        } else {
            throw new InvalidKeyException("OpenSSH Key remaining buffer less than integer length required");
        }

        return integer;
    }
}
