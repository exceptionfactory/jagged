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
package com.exceptionfactory.jagged.framework.codec;

import java.util.Arrays;
import java.util.Base64;

/**
 * Canonical implementation of Base64 Decoder rejects padding and whitespace characters
 */
class CanonicalBase64Decoder implements CanonicalBase64.Decoder {
    private static final Base64.Decoder DECODER = Base64.getDecoder();

    private static final Base64.Encoder ENCODER_WITHOUT_PADDING = Base64.getEncoder().withoutPadding();

    /**
     * Decode byte array containing Base64 characters to standard byte array
     *
     * @param encoded Sequence of RFC 4648 Base64 characters without newlines
     * @return Decoded byte array
     * @throws IllegalArgumentException Thrown when encountering invalid canonical Base64 encoded sources
     */
    @Override
    public byte[] decode(final byte[] encoded) {
        requireValidated(encoded);
        final byte[] decoded = DECODER.decode(encoded);

        final byte[] canonicalEncoded = ENCODER_WITHOUT_PADDING.encode(decoded);
        if (Arrays.equals(canonicalEncoded, encoded)) {
            return decoded;
        }
        throw new IllegalArgumentException("Encoded Base64 padding not allowed");
    }

    private void requireValidated(final byte[] encoded) {
        if (encoded == null) {
            throw new IllegalArgumentException("Encoded Base64 required");
        }
        for (final byte encodedCodePoint : encoded) {
            if (Character.isWhitespace(encodedCodePoint)) {
                throw new IllegalArgumentException("Encoded Base64 whitespace not allowed");
            }
        }
    }
}
