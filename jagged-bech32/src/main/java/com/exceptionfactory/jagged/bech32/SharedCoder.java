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
package com.exceptionfactory.jagged.bech32;

import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.OptionalInt;

/**
 * Shared Bech32 encoding and decoding methods for handling Human-Readable Part validation and character processing
 */
class SharedCoder {
    /** Ordered set of characters for Bech32 representation */
    protected static final String BEC32_CHARACTER_SET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    /** Separator character between Human-Readable Part and encoded Data sections */
    protected static final char PART_SEPARATOR = '1';

    /** Polynomial Modulus Generators */
    protected static final int[] GENERATOR = new int[]{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};

    /** Bech32 Checksum length in bytes */
    protected static final int CHECKSUM_LENGTH = 6;

    protected static final int BECH32_ENCODING_CONSTANT = 1;

    protected static final byte EXPANDED_LOW_BIT_SHIFT = 31;

    protected static final byte EXPANDED_HIGH_BIT_SHIFT = 5;

    private static final int EXPANDED_LENGTH_MULTIPLIER = 2;

    private static final int EXPANDED_SEPARATOR_LENGTH = 1;

    private static final byte EXPANDED_SEPARATOR = 0;

    private static final int INITIAL_COEFFICIENT_BITS = 25;

    private static final int REMAINING_COEFFICIENT_BITS = 0x1ffffff;

    private static final int UNSIGNED_INTEGER_BITS = 255;

    private static final byte MINIMUM_HUMAN_READABLE_PART_ASCII_CODE = 33;

    private static final byte MAXIMUM_HUMAN_READABLE_PART_ASCII_CODE = 126;

    private static final int MAXIMUM_HUMAN_READABLE_PART_LENGTH = 83;

    private static final int MAXIMUM_DATA_LENGTH = 256;

    /**
     * Get Human-Readable Part validated for printable US-ASCII characters
     *
     * @param humanReadablePart Human-Readable Part sequence of characters
     * @return Human-Readable Part sequence of characters unchanged when valid
     * @throws IllegalArgumentException Thrown when invalid characters found
     */
    protected CharSequence getHumanReadablePartValidated(final CharSequence humanReadablePart) {
        Objects.requireNonNull(humanReadablePart, "Human-Readable Part required");

        final int humanReadablePartLength = humanReadablePart.length();
        if (humanReadablePartLength > MAXIMUM_HUMAN_READABLE_PART_LENGTH) {
            final String message = String.format("Human-Readable Part length [%d] greater than maximum [%d]", humanReadablePartLength, MAXIMUM_HUMAN_READABLE_PART_LENGTH);
            throw new IllegalArgumentException(message);
        }

        final OptionalInt invalidCharacterCodeFound = humanReadablePart.codePoints()
                .filter(this::isHumanReadablePartCharacterInvalid)
                .findFirst();

        if (invalidCharacterCodeFound.isPresent()) {
            final int characterCode = invalidCharacterCodeFound.getAsInt();
            final String message = String.format("Human-Readable Part contains invalid character code [%d]", characterCode);
            throw new IllegalArgumentException(message);
        }
        return humanReadablePart;
    }

    /**
     * Get Human-Readable Part expanded to bytes as described in BIP 0173
     *
     * @param humanReadablePart Human-Readble Part sequence of characters
     * @return Expanded bytes derived from high bits and low bits with a separator
     */
    protected byte[] getHumanReadablePartExpanded(final CharSequence humanReadablePart) {
        final int expandedLength = humanReadablePart.length() * EXPANDED_LENGTH_MULTIPLIER + EXPANDED_SEPARATOR_LENGTH;
        final ByteBuffer expanded = ByteBuffer.allocate(expandedLength);

        humanReadablePart.codePoints()
                .map(Character::toLowerCase)
                .map(character -> character >> EXPANDED_HIGH_BIT_SHIFT)
                .forEach(characterHighBits -> expanded.put((byte) characterHighBits));

        expanded.put(EXPANDED_SEPARATOR);

        humanReadablePart.codePoints()
                .map(Character::toLowerCase)
                .map(character -> character & EXPANDED_LOW_BIT_SHIFT)
                .forEach(characterLowBits -> expanded.put((byte) characterLowBits));

        return expanded.array();
    }

    /**
     * Get data bytes converted for encoding or decoding
     *
     * @param data Data bytes to be converted
     * @param conversionMode Conversion mode for encoding or decoding
     * @return Data bytes converted
     */
    protected byte[] getDataConverted(final byte[] data, final ConversionMode conversionMode) {
        final ByteBuffer convertedBuffer = ByteBuffer.allocate(MAXIMUM_DATA_LENGTH);

        int accumulator = 0;
        byte bits = 0;
        for (final byte octet : data) {
            final int octetUnsignedInteger = getUnsignedInteger(octet);
            accumulator = accumulator << conversionMode.inputBits | octetUnsignedInteger;
            bits += conversionMode.inputBits;
            while (bits >= conversionMode.outputBits) {
                bits -= conversionMode.outputBits;
                final int characterConverted = (accumulator >> bits) & conversionMode.maximumOutputBits;
                convertedBuffer.put((byte) characterConverted);
            }
        }

        if (ConversionMode.ENCODING == conversionMode && bits > 0) {
            final int remainingBits = conversionMode.outputBits - bits;
            final int paddingCharacterConverted = accumulator << remainingBits & conversionMode.maximumOutputBits;
            convertedBuffer.put((byte) paddingCharacterConverted);
        }

        final byte[] converted = new byte[convertedBuffer.position()];
        convertedBuffer.flip();
        convertedBuffer.get(converted);
        return converted;
    }

    /**
     * Return lowercase status for sequence of characters
     *
     * @param characters Characters to be evaluated
     * @return Lowercase status when no uppercase characters found
     */
    protected boolean isLowerCase(final CharSequence characters) {
        return characters.codePoints().noneMatch(Character::isUpperCase);
    }

    /**
     * Return uppercase status for sequence of characters
     *
     * @param characters Characters to be evaluated
     * @return Uppercase status when no lowercase characters found
     */
    protected boolean isUpperCase(final CharSequence characters) {
        return characters.codePoints().noneMatch(Character::isLowerCase);
    }

    /**
     * Return existence of any uppercase characters
     *
     * @param characters Characters to be evaluated
     * @return Uppercase characters found
     */
    protected boolean hasUpperCaseCharacters(final CharSequence characters) {
        return characters.codePoints().anyMatch(Character::isUpperCase);
    }

    /**
     * Get polynomial modulus computed from the expanded human-readable part along with data and checksum bytes
     *
     * @param humanReadablePartExpanded Human-Readable Part expanded bytes
     * @param dataDecoded Data bytes decoded
     * @param checksumDecoded Checksum bytes decoded
     * @return Polynomial modulus
     */
    protected int getPolynomialModulus(final byte[] humanReadablePartExpanded, final byte[] dataDecoded, final byte[] checksumDecoded) {
        final int humanReadablePartExpandedModulus = getPolynomialModulus(humanReadablePartExpanded, BECH32_ENCODING_CONSTANT);
        final int dataDecodedModulus = getPolynomialModulus(dataDecoded, humanReadablePartExpandedModulus);
        return getPolynomialModulus(checksumDecoded, dataDecodedModulus);
    }

    private int getPolynomialModulus(final byte[] values, final int initialCoefficient) {
        int packed = initialCoefficient;

        for (final byte value : values) {
            final int firstCoefficient = packed >> INITIAL_COEFFICIENT_BITS;
            packed = (packed & REMAINING_COEFFICIENT_BITS) << EXPANDED_HIGH_BIT_SHIFT;
            packed = packed ^ value;
            for (int i = 0; i < GENERATOR.length; i++) {
                final int firstCoefficientBit = (firstCoefficient >> i) & 1;
                if (firstCoefficientBit == 1) {
                    final int generator = GENERATOR[i];
                    packed ^= generator;
                }
            }
        }

        return packed;
    }

    private boolean isHumanReadablePartCharacterInvalid(final int characterCode) {
        return characterCode < MINIMUM_HUMAN_READABLE_PART_ASCII_CODE || characterCode > MAXIMUM_HUMAN_READABLE_PART_ASCII_CODE;
    }

    private int getUnsignedInteger(final byte octet) {
        return octet & UNSIGNED_INTEGER_BITS;
    }

    protected enum ConversionMode {
        DECODING(5, 8, 255),

        ENCODING(8, 5, 31);

        private final byte inputBits;

        private final byte outputBits;

        private final int maximumOutputBits;

        ConversionMode(final int inputBits, final int outputBits, final int maximumOutputBits) {
            this.inputBits = (byte) inputBits;
            this.outputBits = (byte) outputBits;
            this.maximumOutputBits = maximumOutputBits;
        }
    }
}
