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

/**
 * Bech32 encoding and decoding implementation of Bitcoin Improvement Proposal 0173 for Segregated Witness addresses.
 * The format consists a Base32 alphabet with checksums for error detection.
 * Bech32 addresses consist of human-readable part, a separator, and a data part that contains a checksum.
 */
public final class Bech32 {
    private Bech32() {

    }

    /**
     * Get Bech32 Decoder supporting the original BIP 0173 specification
     *
     * @return Bech32 Decoder
     */
    public static Decoder getDecoder() {
        return new StandardDecoder();
    }

    /**
     * Get Bech32 Encoder supporting the original BIP 0173 specification
     *
     * @return Bech32 Encoder
     */
    public static Encoder getEncoder() {
        return new StandardEncoder();
    }

    /**
     * Bech32 Decoder for encoded sources
     */
    public interface Decoder {
        /**
         * Decode sequence containing Bech32 characters to a Bech32 Address
         *
         * @param encoded Sequence of Bech32 characters with a Human-Readable Part length between 1 and 83
         * @return Bech32 Address
         * @throws IllegalArgumentException Thrown when encountering invalid Bech32 encoded sources
         */
        Bech32Address decode(CharSequence encoded);
    }

    /**
     * Bech32 Encoder for structured Human-Readable Part and Data inputs
     */
    public interface Encoder {
        /**
         * Encode US-ASCII sequence of 1 to 83 Human-Readable Part characters with data bytes as a Bech32 address
         *
         * @param humanReadablePart Sequence with length between 1 and 83 US-ASCII characters within the range of 33 and 126
         * @param data Array of one or more bytes
         * @return Bech32 encoded sequence of characters
         * @throws IllegalArgumentException Thrown when encountering invalid Human-Readable Part characters
         */
        CharSequence encode(CharSequence humanReadablePart, byte[] data);
    }
}
