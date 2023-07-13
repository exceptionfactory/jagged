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
import java.util.Arrays;

/**
 * Standard implementation of Bech32 Decoder based on reference implementations of BIP 0173
 */
class StandardDecoder extends SharedCoder implements Bech32.Decoder {
    private static final int PART_SEPARATOR_OFFSET = 1;

    private static final int CHARACTER_INDEX_NOT_FOUND = -1;

    /**
     * Decode string containing Bech32 characters to a Bech32 Address with Human-Readable Part and Data elements
     *
     * @param encoded String of Bech32 characters
     * @return Bech32 Address
     * @throws IllegalArgumentException Thrown when encountering invalid Bech32 encoded sources
     */
    @Override
    public Bech32Address decode(final CharSequence encoded) {
        final CharSequence normalized = getNormalized(encoded);
        final int partSeparatorIndex = getPartSeparatorIndex(normalized);

        final CharSequence humanReadablePart = getHumanReadablePart(encoded, partSeparatorIndex);
        final byte[] dataChecksumDecoded = getDecoded(normalized, partSeparatorIndex);
        final byte[] dataDecoded = getDataDecoded(dataChecksumDecoded);
        final byte[] checksumDecoded = getChecksumDecoded(dataChecksumDecoded);
        if (isChecksumVerified(humanReadablePart, dataDecoded, checksumDecoded)) {
            final byte[] data = getDataConverted(dataDecoded, ConversionMode.DECODING);
            return new StandardBech32Address(humanReadablePart, data);
        }
        throw new IllegalArgumentException("Bech32 checksum not verified");
    }

    private CharSequence getNormalized(final CharSequence encoded) {
        if (encoded == null) {
            throw new IllegalArgumentException("Encoded Bech32 string required");
        }

        final CharSequence normalized;
        if (isLowerCase(encoded)) {
            normalized = encoded;
        } else if (isUpperCase(encoded)) {
            normalized = getLowerCase(encoded);
        } else {
            throw new IllegalArgumentException("Encoded Bech32 string must be lowercase or uppercase not mixed");
        }

        return normalized;
    }

    private CharSequence getLowerCase(final CharSequence characters) {
        return characters.codePoints()
                .map(Character::toLowerCase)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append);
    }

    private CharSequence getHumanReadablePart(final CharSequence encoded, final int partSeparatorIndex) {
        final CharSequence humanReadablePart = encoded.subSequence(0, partSeparatorIndex);
        return getHumanReadablePartValidated(humanReadablePart);
    }

    private byte[] getDecoded(final CharSequence normalized, final int partSeparatorIndex) {
        final int dataPartStartIndex = partSeparatorIndex + PART_SEPARATOR_OFFSET;
        final CharSequence dataEncoded = normalized.subSequence(dataPartStartIndex, normalized.length());
        return getDecoded(dataEncoded);
    }

    private byte[] getChecksumDecoded(final byte[] dataChecksumDecoded) {
        final int checksumStartIndex = dataChecksumDecoded.length - CHECKSUM_LENGTH;
        return Arrays.copyOfRange(dataChecksumDecoded, checksumStartIndex, dataChecksumDecoded.length);
    }

    private byte[] getDataDecoded(final byte[] dataChecksumDecoded) {
        final int dataEndIndex = dataChecksumDecoded.length - CHECKSUM_LENGTH;
        return Arrays.copyOfRange(dataChecksumDecoded, 0, dataEndIndex);
    }

    private byte[] getDecoded(final CharSequence charactersEncoded) {
        final int[] characters = charactersEncoded.codePoints().toArray();

        final ByteBuffer decoded = ByteBuffer.allocate(characters.length);
        for (int characterEncoded : characters) {
            final int characterDecoded = BEC32_CHARACTER_SET.indexOf(characterEncoded);
            if (characterDecoded == CHARACTER_INDEX_NOT_FOUND) {
                final String message = String.format("Bech32 Data character [%d] not valid", characterEncoded);
                throw new IllegalArgumentException(message);
            }
            decoded.put((byte) characterDecoded);
        }

        final byte[] charactersDecoded = new byte[decoded.position()];
        decoded.flip();
        decoded.get(charactersDecoded);
        return charactersDecoded;
    }

    private int getPartSeparatorIndex(final CharSequence encoded) {
        final int checksumStartIndex = encoded.length() - CHECKSUM_LENGTH;
        final int endIndex = encoded.length() - 1;
        for (int index = endIndex; index > 0; index--) {
            final char character = encoded.charAt(index);
            if (character == PART_SEPARATOR) {
                if (index >= checksumStartIndex) {
                    final String message = String.format("Bech32 Part Separator [1] position [%d] found in checksum", index);
                    throw new IllegalArgumentException(message);
                }
                return index;
            }
        }
        throw new IllegalArgumentException("Bech32 Part Separator [1] not found");
    }

    private boolean isChecksumVerified(final CharSequence humanReadablePart, final byte[] dataDecoded, final byte[] checksumDecoded) {
        final byte[] humanReadablePartExpanded = getHumanReadablePartExpanded(humanReadablePart);
        final int polynomialModulus = getPolynomialModulus(humanReadablePartExpanded, dataDecoded, checksumDecoded);
        return BECH32_ENCODING_CONSTANT == polynomialModulus;
    }
}
