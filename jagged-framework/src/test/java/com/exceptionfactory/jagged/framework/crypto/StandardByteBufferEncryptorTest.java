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

class StandardByteBufferEncryptorTest {
    static final byte[] INPUT = new byte[]{0, 1, 2, 3};

    static final byte[] EXPECTED_OUTPUT = new byte[]{75, -23, -98, 103, 100, 11, 71, 7, 38, 115, -38, -46, 11, -73, 78, -45, 13, -4, -82, -6};

    @Test
    void testEncrypt() throws GeneralSecurityException {
        final CipherKey cipherKey = new CipherKey(CipherKeyTest.SYMMETRIC_KEY);
        final IvParameterSpec parameterSpec = new IvParameterSpec(CipherFactoryTest.INITIALIZATION_VECTOR);

        final CipherFactory cipherFactory = new CipherFactory();
        final StandardByteBufferEncryptor encryptor = new StandardByteBufferEncryptor(cipherFactory, cipherKey, parameterSpec);

        final ByteBuffer inputBuffer = ByteBuffer.wrap(INPUT);
        final ByteBuffer outputBuffer = ByteBuffer.allocate(EXPECTED_OUTPUT.length);

        final int encryptedLength = encryptor.encrypt(inputBuffer, outputBuffer);

        assertEquals(EXPECTED_OUTPUT.length, encryptedLength);
        final byte[] output = outputBuffer.array();
        assertArrayEquals(EXPECTED_OUTPUT, output);
    }
}
