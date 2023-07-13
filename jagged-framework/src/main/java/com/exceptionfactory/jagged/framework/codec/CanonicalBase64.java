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

/**
 * Canonical Base64 Decoder implements RFC 4648 Section 3.5 canonical encoding and decoding without padding
 */
public final class CanonicalBase64 {
    private static final Decoder DECODER = new CanonicalBase64Decoder();

    private static final Encoder ENCODER = new CanonicalBase64Encoder();

    private CanonicalBase64() {

    }

    /**
     * Get Canonical Base64 Decoder sharable instance can be reused
     *
     * @return Reusable Base64 Decoder
     */
    public static Decoder getDecoder() {
        return DECODER;
    }

    /**
     * Get Canonical Base64 Encoder sharable instance can be reused
     *
     * @return Reusable Base64 Encoder
     */
    public static Encoder getEncoder() {
        return ENCODER;
    }

    /**
     * Canonical Base64 Decoder for encoded sources
     */
    public interface Decoder {
        /**
         * Decode byte array containing Base64 characters to standard byte array
         *
         * @param encoded Sequence of RFC 4648 Base64 characters without newlines
         * @return Decoded byte array
         * @throws IllegalArgumentException Thrown when encountering invalid canonical Base64 encoded sources
         */
        byte[] decode(byte[] encoded);
    }

    /**
     * Canonical Base64 Encoder following RFC 4648 Section 3.5
     */
    public interface Encoder {
        /**
         * Encode byte array as Base64 characters from standard byte array
         *
         * @param source Sequence of bytes to be encoded
         * @return Base64 encoded byte array
         * @throws IllegalArgumentException Thrown when encountering invalid sources
         */
        byte[] encode(byte[] source);

        /**
         * Encode byte array to Base64 character string from standard byte array
         *
         * @param source Sequence of bytes to be encoded
         * @return Base64 encoded string
         * @throws IllegalArgumentException Thrown when encountering invalid sources
         */
        String encodeToString(byte[] source);
    }
}
