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
import java.nio.ByteOrder;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class Salsa20RoundReducedFunctionTest {
    private static final int[] EMPTY_VECTOR = new int[]{};

    private static final String SPACE_SEPARATOR = " ";

    private static final int HEXADECIMAL_RADIX = 16;

    private static final int BYTE_VECTOR_LENGTH_MULTIPLIER = 16;

    private static final int VECTOR_LENGTH_MULTIPLIER = 4;

    /** RFC 7914 Section 8 Input Test Vector for Salsa 20 */
    private static final String[] INPUT_VECTOR = new String[]{
            "7e 87 9a 21 4f 3e c9 86 7c a9 40 e6 41 71 8f 26",
            "ba ee 55 5b 8c 61 c1 b5 0d f8 46 11 6d cd 3b 1d",
            "ee 24 f3 19 df 9b 3d 85 14 12 1e 4b 5a c5 aa 32",
            "76 02 1d 29 09 c7 48 29 ed eb c6 8d b8 b8 c2 5e"
    };

    /** RFC 7914 Section 8 Output Test Vector for Salsa 20 */
    private static final String[] OUTPUT_VECTOR = new String[]{
            "a4 1f 85 9c 66 08 cc 99 3b 81 ca cb 02 0c ef 05",
            "04 4b 21 81 a2 fd 33 7d fd 7b 1c 63 96 68 2f 29",
            "b4 39 31 68 e3 c9 e6 bc fe 6b c5 b7 a0 6d 96 ba",
            "e4 24 cc 10 2c 91 74 5c 24 ad 67 3d c7 61 8f 81"
    };

    @Test
    void testVector() {
        final int[] inputVector = getVector(INPUT_VECTOR);
        final int[] outputVector = getVector(OUTPUT_VECTOR);

        final int[] hash = Salsa20RoundReducedFunction.getHash(inputVector);

        assertArrayEquals(outputVector, hash);
    }

    @Test
    void testInputLengthException() {
        assertThrows(IllegalArgumentException.class, () -> Salsa20RoundReducedFunction.getHash(EMPTY_VECTOR));
    }

    static int[] getVector(final String[] lines) {
        final int byteBufferLength = lines.length * BYTE_VECTOR_LENGTH_MULTIPLIER;
        final ByteBuffer buffer = ByteBuffer.allocate(byteBufferLength);

        for (final String vector : lines) {
            for (final String hexadecimal : vector.split(SPACE_SEPARATOR)) {
                final int decoded = Integer.parseInt(hexadecimal, HEXADECIMAL_RADIX);
                buffer.put((byte) decoded);
            }
        }

        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.flip();

        final int vectorLength = lines.length * VECTOR_LENGTH_MULTIPLIER;
        final int[] vector = new int[vectorLength];
        int index = 0;
        while (buffer.hasRemaining()) {
            final int word = buffer.getInt();
            vector[index] = word;
            index++;
        }

        return vector;
    }
}
