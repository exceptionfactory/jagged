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

import java.util.Objects;

/**
 * Salsa20 round-reduced hash function with 8 rounds defined in Salsa20 Section 8 and described in RFC 7914 Section 3
 */
final class Salsa20RoundReducedFunction {
    private static final int SEQUENCE_LENGTH = 16;

    private static final int SALSA20_ROUNDS = 8;

    private static final int ROUND_INCREMENT = 2;

    private static final int QUARTER_ROUND_7 = 7;

    private static final int QUARTER_ROUND_9 = 9;

    private static final int QUARTER_ROUND_13 = 13;

    private static final int QUARTER_ROUND_18 = 18;

    private static final int FIRST_INDEX = 0;

    private static final int SECOND_INDEX = 1;

    private static final int THIRD_INDEX = 2;

    private static final int FOURTH_INDEX = 3;

    /** Hash Word Indices listed in RFC 7914 Section 3 */
    private static final int[][] HASH_WORD_INDICES = new int[][]{
            new int[]{4, 8, 12, 0},
            new int[]{9, 13, 1, 5},
            new int[]{14, 2, 6, 10},
            new int[]{3, 7, 11, 15},
            new int[]{1, 2, 3, 0},
            new int[]{6, 7, 4, 5},
            new int[]{11, 8, 9, 10},
            new int[]{12, 13, 14, 15},
    };

    private Salsa20RoundReducedFunction() {

    }

    /**
     * Run Salsa20 Section 8 hash using 8 rounds operating on 64-byte sequences represented as an array of 16 integers
     *
     * @param input Input array of 16 integers representing a sequence of 64 bytes
     * @return Output array of 16 integers containing the hash according to Salsa20 Section 8
     */
    static int[] getHash(final int[] input) {
        Objects.requireNonNull(input, "Input sequence required");

        if (input.length == SEQUENCE_LENGTH) {
            return getHashSalsa20(input);
        } else {
            final String message = String.format("Input sequence length [%d] not equal to required length [%d]", input.length, SEQUENCE_LENGTH);
            throw new IllegalArgumentException(message);
        }
    }

    private static int[] getHashSalsa20(final int[] input) {
        final int[] working = new int[input.length];
        System.arraycopy(input, 0, working, 0, working.length);

        for (int i = SALSA20_ROUNDS; i > 0; i -= ROUND_INCREMENT) {
            for (final int[] indices : HASH_WORD_INDICES) {
                quarterRound(working, indices[FIRST_INDEX], indices[SECOND_INDEX], indices[THIRD_INDEX], indices[FOURTH_INDEX]);
            }
        }

        final int[] hash = new int[SEQUENCE_LENGTH];
        for (int i = 0; i < hash.length; i++) {
            hash[i] = working[i] + input[i];
        }

        return hash;
    }

    private static void quarterRound(final int[] working, final int index0, final int index1, final int index2, final int index3) {
        working[index0] ^= Integer.rotateLeft(working[index3] + working[index2], QUARTER_ROUND_7);
        working[index1] ^= Integer.rotateLeft(working[index0] + working[index3], QUARTER_ROUND_9);
        working[index2] ^= Integer.rotateLeft(working[index1] + working[index0], QUARTER_ROUND_13);
        working[index3] ^= Integer.rotateLeft(working[index2] + working[index1], QUARTER_ROUND_18);
    }
}
