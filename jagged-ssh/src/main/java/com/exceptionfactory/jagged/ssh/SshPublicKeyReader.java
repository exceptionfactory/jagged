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
import java.security.InvalidKeyException;
import java.security.PublicKey;

/**
 * SSH Public Key Reader with shared methods
 *
 * @param <T> Public Key Type
 */
abstract class SshPublicKeyReader<T extends PublicKey> implements PublicKeyReader<T> {
    /**
     * Read length-delimited array of bytes
     *
     * @param buffer Byte buffer to be read
     * @return Byte array read
     * @throws InvalidKeyException Thrown on invalid number of bytes indicated to be read
     */
    protected byte[] readBlock(final ByteBuffer buffer) throws InvalidKeyException {
        final int length = buffer.getInt();
        if (length > buffer.remaining()) {
            throw new InvalidKeyException(String.format("Public Key block length [%d] not valid", length));
        }

        final byte[] block = new byte[length];
        buffer.get(block);
        return block;
    }
}
