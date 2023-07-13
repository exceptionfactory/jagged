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
package com.exceptionfactory.jagged.scrypt;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ScryptFunctionTest {
    private static final String SPACE_SEPARATOR = " ";

    private static final int HEXADECIMAL_RADIX = 16;

    private static final int BYTE_VECTOR_LENGTH_MULTIPLIER = 16;

    private static final Charset VECTOR_CHARACTER_SET = StandardCharsets.UTF_8;

    private static final String VECTOR_PASSWORD = "pleaseletmein";

    private static final String VECTOR_SALT = "SodiumChloride";

    private static final int VECTOR_WORK_FACTOR = 14;

    private static final int WORK_FACTOR_GREATER_THAN_MAXIMUM = 21;

    private static final int WORK_FACTOR_LESS_THAN_MINIMUM = 1;

    private static final String[] OUTPUT_VECTOR = new String[]{
            "70 23 bd cb 3a fd 73 48 46 1c 06 cd 81 fd 38 eb",
            "fd a8 fb ba 90 4f 8e 3e a9 b5 43 f6 54 5d a1 f2"
    };

    @Test
    void testWorkFactorGreaterThanMaximum() {
        final byte[] passphrase = VECTOR_PASSWORD.getBytes(VECTOR_CHARACTER_SET);
        final byte[] salt = VECTOR_SALT.getBytes(VECTOR_CHARACTER_SET);

        assertThrows(IllegalArgumentException.class, () -> ScryptFunction.getDerivedKey(passphrase, salt, WORK_FACTOR_GREATER_THAN_MAXIMUM));
    }

    @Test
    void testWorkFactorLessThanMinimum() {
        final byte[] passphrase = VECTOR_PASSWORD.getBytes(VECTOR_CHARACTER_SET);
        final byte[] salt = VECTOR_SALT.getBytes(VECTOR_CHARACTER_SET);

        assertThrows(IllegalArgumentException.class, () -> ScryptFunction.getDerivedKey(passphrase, salt, WORK_FACTOR_LESS_THAN_MINIMUM));
    }

    @Test
    void testVector() throws GeneralSecurityException {
        final byte[] outputVector = getOutputVector(OUTPUT_VECTOR);

        final byte[] passphrase = VECTOR_PASSWORD.getBytes(VECTOR_CHARACTER_SET);
        final byte[] salt = VECTOR_SALT.getBytes(VECTOR_CHARACTER_SET);
        final byte[] customDerived = ScryptFunction.getDerivedKey(passphrase, salt, VECTOR_WORK_FACTOR);

        assertArrayEquals(outputVector, customDerived);
    }

    static byte[] getOutputVector(final String[] lines) {
        final int byteBufferLength = lines.length * BYTE_VECTOR_LENGTH_MULTIPLIER;
        final ByteBuffer buffer = ByteBuffer.allocate(byteBufferLength);

        for (final String vector : lines) {
            for (final String hexadecimal : vector.split(SPACE_SEPARATOR)) {
                final int decoded = Integer.parseInt(hexadecimal, HEXADECIMAL_RADIX);
                buffer.put((byte) decoded);
            }
        }

       return buffer.array();
    }
}
