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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class Bech32Test {
    private static final char SEPARATOR = '1';

    private static final int DELETE_CODE_POINT = 127;

    private static final int EURO_SIGN_CODE_POINT = 128;

    private static final byte[] EMPTY_DATA = new byte[0];

    private Bech32.Decoder decoder;

    private Bech32.Encoder encoder;

    @BeforeEach
    void setDecoder() {
        decoder = Bech32.getDecoder();
        encoder = Bech32.getEncoder();
    }

    @Test
    void testVectorUpperCaseValid() {
        assertValid("A12UEL5L");
    }

    @Test
    void testVectorLowerCaseValid() {
        assertValid("a12uel5l");
    }

    @Test
    void testVectorLowerCaseLongValid() {
        assertValid("an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs");
    }

    @Test
    void testVectorLowerCaseShortValid() {
        assertValid("abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw");
    }

    @Test
    void testVectorLowerCaseSeparatorUsedValid() {
        assertValid("11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j");
    }

    @Test
    void testVectorLowerCaseWordsValid() {
        assertValid("split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w");
    }

    @Test
    void testVectorLowerCaseQuestionMarkValid() {
        assertValid("?1ezyfcl");
    }

    @Test
    void testVectorSpaceCharacterInvalid() {
        assertInvalid(" 1nwldj5");
    }

    @Test
    void testVectorDeleteCharacterInvalid() {
        final StringBuilder encoded = new StringBuilder();
        encoded.appendCodePoint(DELETE_CODE_POINT);
        encoded.append("1nwldj5");
        assertInvalid(encoded);
    }

    @Test
    void testVectorEuroSignCharacterInvalid() {
        final StringBuilder encoded = new StringBuilder();
        encoded.appendCodePoint(EURO_SIGN_CODE_POINT);
        encoded.append("1nwldj5");
        assertInvalid(encoded);
    }

    @Test
    void testVectorLengthInvalid() {
        assertInvalid("an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx");
    }

    @Test
    void testVectorSeparatorNotFoundInvalid() {
        assertInvalid("pzry9x0s0muk");
    }

    @Test
    void testVectorHumanReadablePartNotFoundInvalid() {
        assertInvalid("1pzry9x0s0muk");
    }

    @Test
    void testVectorDataCharacterInvalid() {
        assertInvalid("x1b4n0q5v");
    }

    @Test
    void testVectorChecksumShortInvalid() {
        assertInvalid("li1dgmt3");
    }

    @Test
    void testVectorChecksumUpperCaseHumanReadablePartInvalid() {
        assertInvalid("A1G7SGD8");
    }

    @Test
    void testVectorHumanReadablePartEmptyInvalid() {
        assertInvalid("10a06t8");
    }

    @Test
    void testVectorHumanReadablePartMissingInvalid() {
        assertInvalid("1qzzfhee");
    }

    @Test
    void testNullInvalid() {
        assertInvalid(null);
    }

    @Test
    void testMixedCaseInvalid() {
        assertInvalid("Abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw");
    }

    @Test
    void testEncodeHumanReadablePartInvalid() {
        final StringBuilder builder = new StringBuilder();
        builder.appendCodePoint(EURO_SIGN_CODE_POINT);
        final String humanReadablePart = builder.toString();

        assertThrows(IllegalArgumentException.class, () -> encoder.encode(humanReadablePart, EMPTY_DATA));
    }

    @Test
    void testEncodeLowerCaseValid() {
        final String expected = "a12uel5l";
        final String humanReadablePart = "a";

        final CharSequence encoded = encoder.encode(humanReadablePart, EMPTY_DATA);

        assertEquals(expected, encoded);
    }

    @Test
    void testEncodeLowerCaseDataDecodeValid() {
        final String humanReadablePart = "a";
        final byte[] data = new byte[]{1, 2, 3};
        final String addressEncoded = "a1qypqxwe0h93";

        final CharSequence encoded = encoder.encode(humanReadablePart, data);

        assertEquals(addressEncoded, encoded);

        final Bech32Address decoded = decoder.decode(encoded);

        assertEquals(humanReadablePart, decoded.getHumanReadablePart());
        assertArrayEquals(data, decoded.getData());
    }

    @Test
    void testEncodeUpperCaseValid() {
        final String expected = "A12UEL5L";
        final String humanReadablePart = "A";

        final CharSequence encoded = encoder.encode(humanReadablePart, EMPTY_DATA);

        assertEquals(expected, encoded);
    }

    @Test
    void testEncodeQuestionMarkValid() {
        final String expected = "?1ezyfcl";
        final String humanReadablePart = "?";

        final CharSequence encoded = encoder.encode(humanReadablePart, EMPTY_DATA);

        assertEquals(expected, encoded);
    }

    @Test
    void testEncodeMixedCaseHumanReadablePartInvalid() {
        final String humanReadablePart = "Aa";

        assertThrows(IllegalArgumentException.class, () -> encoder.encode(humanReadablePart, EMPTY_DATA));
    }

    @Test
    void testEncodeHumanReadablePartLengthInvalid() {
        final String humanReadablePart = "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio";

        assertThrows(IllegalArgumentException.class, () -> encoder.encode(humanReadablePart, EMPTY_DATA));
    }

    void assertInvalid(final CharSequence encoded) {
        assertThrows(IllegalArgumentException.class, () -> decoder.decode(encoded));
    }

    void assertValid(final String encoded) {
        final Bech32Address decoded = decoder.decode(encoded);
        assertNotNull(decoded);
        assertNotNull(decoded.getData());

        assertHumanReadablePartEquals(encoded, decoded);

        final CharSequence encodedSequence = encoder.encode(decoded.getHumanReadablePart(), decoded.getData());
        assertEquals(encoded, encodedSequence);
    }

    void assertHumanReadablePartEquals(final String encoded, final Bech32Address decoded) {
        final int separatorIndex = encoded.lastIndexOf(SEPARATOR);
        final String humanReadablePart = encoded.substring(0, separatorIndex);
        assertEquals(humanReadablePart, decoded.getHumanReadablePart());
    }
}
