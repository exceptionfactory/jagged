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

/**
 * Standard implementation of Bech32 Encoder based on reference implementation of BIP 0173
 */
class StandardEncoder extends SharedCoder implements Bech32.Encoder {
    /**
     * Encode US-ASCII sequence of 1 to 83 Human-Readable Part characters with data bytes as a Bech32 string
     *
     * @param humanReadablePart Sequence with length between 1 and 83 US-ASCII characters within the range of 33 and 126
     * @param data Array of one or more bytes
     * @return Bech32 encoded sequence of characters with casing based in human-readable part casing
     * @throws IllegalArgumentException Thrown when encountering invalid Human-Readable Part characters
     */
    @Override
    public CharSequence encode(final CharSequence humanReadablePart, final byte[] data) {
        final CharSequence validatedHumanReadablePart = getHumanReadablePartValidated(humanReadablePart);
        Objects.requireNonNull(data, "Data required");

        final boolean upperCaseRequired = isUpperCaseRequired(humanReadablePart);
        final StringBuilder builder = new StringBuilder();
        builder.append(validatedHumanReadablePart);
        builder.append(PART_SEPARATOR);
        final byte[] dataConverted = getDataConverted(data, ConversionMode.ENCODING);
        appendEncoded(builder, dataConverted);

        final byte[] checksum = getChecksum(validatedHumanReadablePart, dataConverted);
        appendEncoded(builder, checksum);

        return getEncoded(builder, upperCaseRequired);
    }

    private String getEncoded(final StringBuilder builder, final boolean upperCaseRequired) {
        final String lowerCaseEncoded = builder.toString();
        final String encoded;
        if (upperCaseRequired) {
            encoded = lowerCaseEncoded.toUpperCase();
        } else {
            encoded = lowerCaseEncoded;
        }
        return encoded;
    }

    private boolean isUpperCaseRequired(final CharSequence humanReadablePart) {
        final boolean upperCaseRequired;
        if (hasUpperCaseCharacters(humanReadablePart)) {
            if (isUpperCase(humanReadablePart)) {
                upperCaseRequired = true;
            } else {
                throw new IllegalArgumentException("Encoded Bech32 string must be lowercase or uppercase not mixed");
            }
        } else {
            upperCaseRequired = false;
        }
        return upperCaseRequired;
    }

    private void appendEncoded(final StringBuilder builder, final byte[] values) {
        for (final byte value : values) {
            final char valueEncoded = BEC32_CHARACTER_SET.charAt(value);
            builder.append(valueEncoded);
        }
    }

    private byte[] getChecksum(final CharSequence humanReadablePart, final byte[] data) {
        final byte[] humanReadablePartExpanded = getHumanReadablePartExpanded(humanReadablePart);
        final byte[] emptyChecksum = new byte[CHECKSUM_LENGTH];
        final int polynomialModulus = getPolynomialModulus(humanReadablePartExpanded, data, emptyChecksum);
        final int modulus = polynomialModulus ^ BECH32_ENCODING_CONSTANT;

        final ByteBuffer checksumBuffer = ByteBuffer.allocate(CHECKSUM_LENGTH);

        for (int i = 0; i < CHECKSUM_LENGTH; i++) {
            final int shift = EXPANDED_HIGH_BIT_SHIFT * (EXPANDED_HIGH_BIT_SHIFT - i);
            final int checksumElement = (modulus >> shift) & EXPANDED_LOW_BIT_SHIFT;
            final byte checksumByte = (byte) checksumElement;
            checksumBuffer.put(checksumByte);
        }

        return checksumBuffer.array();
    }
}
