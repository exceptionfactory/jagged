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
package com.exceptionfactory.jagged.framework.crypto;

import org.junit.jupiter.api.Test;

import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class StandardByteBufferDecryptorTest {
    private static final byte[] SYMMETRIC_KEY = new byte[]{
            1, 2, 3, 4, 5, 6, 7, 8,
            1, 2, 3, 4, 5, 6, 7, 8,
            1, 2, 3, 4, 5, 6, 7, 8,
            1, 2, 3, 4, 5, 6, 7, 8
    };

    private static final byte[] INPUT = StandardByteBufferEncryptorTest.EXPECTED_OUTPUT;

    private static final byte[] EXPECTED_OUTPUT = StandardByteBufferEncryptorTest.INPUT;

    @Test
    void testDecrypt() throws GeneralSecurityException {
        final CipherKey cipherKey = new CipherKey(SYMMETRIC_KEY);
        final IvParameterSpec parameterSpec = new IvParameterSpec(CipherFactoryTest.INITIALIZATION_VECTOR);

        final StandardByteBufferDecryptor decryptor = new StandardByteBufferDecryptor(cipherKey, parameterSpec);

        final ByteBuffer inputBuffer = ByteBuffer.wrap(INPUT);
        final ByteBuffer outputBuffer = ByteBuffer.allocate(EXPECTED_OUTPUT.length);

        final int encryptedLength = decryptor.decrypt(inputBuffer, outputBuffer);

        assertEquals(EXPECTED_OUTPUT.length, encryptedLength);
        final byte[] output = outputBuffer.array();
        assertArrayEquals(EXPECTED_OUTPUT, output);
    }
}
