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

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.util.Objects;

/**
 * scrypt key derivation algorithm as described RFC 7914 with predefined settings for age encryption
 */
final class ScryptFunction {
    /** Derived Key length defaulted to 32 for age encryption */
    private static final int DERIVED_KEY_LENGTH = 32;

    /** Cost Base for calculation using Work Factor exponent */
    private static final int COST_BASE = 2;

    /** Maximum Work Factor is 20 to avoid array size overflow */
    private static final int MAX_WORK_FACTOR = 20;

    /** Minimum Work Factory is 2 to provide minimum security */
    private static final int MIN_WORK_FACTOR = 2;

    /** Block Size parameter r defaulted to 8 for age encryption */
    private static final int BLOCK_SIZE = 8;

    /** Block Size parameter doubled for block mixing function */
    private static final int BLOCK_SIZE_DOUBLED = 16;

    /** Block Size octet length equals Block Size parameter r of 8 and Parallelization of 1 multiplied by 128 */
    private static final int BLOCK_SIZE_OCTET_LENGTH = 1024;

    /** Random Oracle mixed length for mixing function is double the block size octet length */
    private static final int RANDOM_ORACLE_MIXED_LENGTH = 2048;

    /** Last octet block offset used for deriving unsigned integer in block mixing function */
    private static final int LAST_OCTET_BLOCK_OFFSET = 960;

    private static final int MIXED_BLOCK_OFFSET = 512;

    private static final int OCTET_BLOCK_LENGTH = 64;

    private static final int OCTET_BLOCK_LENGTH_DOUBLED = 128;

    private static final int WORD_BLOCK_LENGTH = 16;

    private static final int WORD_LENGTH = 4;

    private ScryptFunction() {

    }

    /**
     * Get Derived Key of 32 bytes using provided parameters with predefined Block Size of 8 and Parallelization of 1
     *
     * @param passphrase Passphrase bytes
     * @param salt       Random salt bytes
     * @param workFactor Work Factor exponent power of 2 for deriving CPU and Memory Cost Parameter
     * @return Derived Key array of 32 bytes
     * @throws GeneralSecurityException Thrown on key derivation failures
     */
    public static byte[] getDerivedKey(final byte[] passphrase, final byte[] salt, final int workFactor) throws GeneralSecurityException {
        Objects.requireNonNull(passphrase, "Passphrase required");
        Objects.requireNonNull(salt, "Salt required");
        requireValidWorkFactor(workFactor);

        final byte[] block = PasswordBasedKeyDerivationFunction2.getDerivedKey(passphrase, salt, BLOCK_SIZE_OCTET_LENGTH);

        final int cost = getCost(workFactor);
        getRandomOracleMixed(block, cost);

        return PasswordBasedKeyDerivationFunction2.getDerivedKey(passphrase, block, DERIVED_KEY_LENGTH);
    }

    /**
     * Process array of bytes using random oracle mixing described in RFC 7914 Section 5
     *
     * @param block Initialized array block of 1024 bytes to be updated with Random Oracle Mixed bytes
     * @param cost Cost parameter computed from Work Factor exponent power of 2
     */
    private static void getRandomOracleMixed(final byte[] block, final int cost) {
        final byte[] mixed = new byte[RANDOM_ORACLE_MIXED_LENGTH];
        System.arraycopy(block, 0, mixed, 0, block.length);

        final int costBlockLength = BLOCK_SIZE_OCTET_LENGTH * cost;
        final byte[] costBlocks = new byte[costBlockLength];

        for (int i = 0; i < cost; ++i) {
            final int blockStartIndex = i * BLOCK_SIZE_OCTET_LENGTH;
            System.arraycopy(mixed, 0, costBlocks, blockStartIndex, BLOCK_SIZE_OCTET_LENGTH);
            getMixedBlock(mixed);
        }

        final ByteBuffer lastOctetBlockBuffer = ByteBuffer.wrap(mixed, LAST_OCTET_BLOCK_OFFSET, WORD_LENGTH).order(ByteOrder.LITTLE_ENDIAN);
        final int costMask = cost - 1;
        for (int i = 0; i < cost; ++i) {
            // Get unsigned integer using little endian byte order as described in RFC 7914 Section 5
            lastOctetBlockBuffer.mark();
            final int lastWord = lastOctetBlockBuffer.getInt();
            final int unsignedLastWord = lastWord & costMask;
            lastOctetBlockBuffer.reset();

            final int blockStartIndex = unsignedLastWord * BLOCK_SIZE_OCTET_LENGTH;
            exclusiveOrBlock(costBlocks, blockStartIndex, mixed, BLOCK_SIZE_OCTET_LENGTH);
            getMixedBlock(mixed);
        }

        System.arraycopy(mixed, 0, block, 0, BLOCK_SIZE_OCTET_LENGTH);
    }

    /**
     * Process array of bytes using block mixing described in RFC 7914 Section 4
     *
     * @param mixed Mixed array of bytes to be updated based on Salsa20 Section 8 hashing with block mixing
     */
    private static void getMixedBlock(final byte[] mixed) {
        byte[] block = new byte[OCTET_BLOCK_LENGTH];
        System.arraycopy(mixed, LAST_OCTET_BLOCK_OFFSET, block, 0, OCTET_BLOCK_LENGTH);

        for (int i = 0; i < BLOCK_SIZE_DOUBLED; ++i) {
            final int blockStartIndex = i * OCTET_BLOCK_LENGTH;
            exclusiveOrBlock(mixed, blockStartIndex, block, OCTET_BLOCK_LENGTH);

            final int[] wordBlock = getWordBlock(block);
            final int[] hash = Salsa20RoundReducedFunction.getHash(wordBlock);
            block = getOctetBlock(hash);

            final int destinationPosition = BLOCK_SIZE_OCTET_LENGTH + blockStartIndex;
            System.arraycopy(block, 0, mixed, destinationPosition, OCTET_BLOCK_LENGTH);
        }

        for (int i = 0; i < BLOCK_SIZE; ++i) {
            final int initialSourcePosition = i * OCTET_BLOCK_LENGTH_DOUBLED;
            final int firstSourcePosition = BLOCK_SIZE_OCTET_LENGTH + initialSourcePosition;
            final int firstDestinationPosition = i * OCTET_BLOCK_LENGTH;
            System.arraycopy(mixed, firstSourcePosition, mixed, firstDestinationPosition, OCTET_BLOCK_LENGTH);

            final int secondSourcePosition = firstSourcePosition + OCTET_BLOCK_LENGTH;
            final int secondDestinationPosition = firstDestinationPosition + MIXED_BLOCK_OFFSET;
            System.arraycopy(mixed, secondSourcePosition, mixed, secondDestinationPosition, OCTET_BLOCK_LENGTH);
        }
    }

    private static void exclusiveOrBlock(final byte[] sourceBlock, final int startIndex, final byte[] destinationBlock, final int length) {
        for (int i = 0; i < length; ++i) {
            destinationBlock[i] ^= sourceBlock[startIndex + i];
        }
    }

    private static int[] getWordBlock(final byte[] octets) {
        final ByteBuffer wordBuffer = ByteBuffer.wrap(octets).order(ByteOrder.LITTLE_ENDIAN);

        final int[] words = new int[WORD_BLOCK_LENGTH];
        int index = 0;
        while (wordBuffer.hasRemaining()) {
            words[index] = wordBuffer.getInt();
            index++;
        }

        return words;
    }

    private static byte[] getOctetBlock(final int[] words) {
        final ByteBuffer octetBuffer = ByteBuffer.allocate(OCTET_BLOCK_LENGTH).order(ByteOrder.LITTLE_ENDIAN);

        for (final int word : words) {
            octetBuffer.putInt(word);
        }

        return octetBuffer.array();
    }

    private static int getCost(final int workFactor) {
        final double cost = Math.pow(COST_BASE, workFactor);
        return Math.toIntExact(Math.round(cost));
    }

    private static void requireValidWorkFactor(final int workFactor) {
        if (workFactor > MAX_WORK_FACTOR) {
            throw new IllegalArgumentException(String.format("Work Factor [%d] greater than maximum [%d]", workFactor, MAX_WORK_FACTOR));
        } else if (workFactor < MIN_WORK_FACTOR) {
            throw new IllegalArgumentException(String.format("Work Factor [%d] less than minimum [%d]", workFactor, MIN_WORK_FACTOR));
        }
    }
}
