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

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class PasswordBasedKeyDerivationFunction2Test {
    private static final Charset CHARACTER_SET = StandardCharsets.US_ASCII;

    private static final String PASSPHRASE = "passwd";

    private static final String SALT = "salt";

    private static final int DERIVED_KEY_LENGTH = 64;

    /** RFC 7914 Section 11 Input Test Vector for PBKDF2-HMAC-SHA-256 */
    private static final String[] SINGLE_ITERATION_VECTOR = new String[]{
            "55 ac 04 6e 56 e3 08 9f ec 16 91 c2 25 44 b6 05",
            "f9 41 85 21 6d de 04 65 e6 8b 9d 57 c2 0d ac bc",
            "49 ca 9c cc f1 79 b6 45 99 16 64 b3 9d 77 ef 31",
            "7c 71 b8 45 b1 e3 0b d5 09 11 20 41 d3 a1 97 83"
    };

    @Test
    void testVector() throws GeneralSecurityException {
        final byte[] outputVector = ScryptFunctionTest.getOutputVector(SINGLE_ITERATION_VECTOR);

        final byte[] password = PASSPHRASE.getBytes(CHARACTER_SET);
        final byte[] salt = SALT.getBytes(CHARACTER_SET);
        final byte[] derivedKey = PasswordBasedKeyDerivationFunction2.getDerivedKey(password, salt, DERIVED_KEY_LENGTH);

        assertArrayEquals(outputVector, derivedKey);
    }
}
