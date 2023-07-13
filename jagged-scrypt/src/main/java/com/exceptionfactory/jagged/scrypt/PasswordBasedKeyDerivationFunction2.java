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

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

/**
 * Password-Based Key Derivation Function 2 with HMAC-SHA-256 and single iteration for scrypt as described in RFC 7914
 */
final class PasswordBasedKeyDerivationFunction2 {
    /** PBKDF2 with HMAC-SHA-256 for scrypt as described in RFC 7914 Section 6 */
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";

    /** Single Iteration for PBKDF2 */
    private static final int SINGLE_ITERATION = 1;

    /** Bit Length Multiplier */
    private static final int BIT_LENGTH_MULTIPLIER = 8;

    /** Passphrase Character Set */
    private static final Charset PASSPHRASE_CHARACTER_SET = StandardCharsets.UTF_8;

    private PasswordBasedKeyDerivationFunction2() {

    }

    /**
     * Get Derived Key using password with salt and specified key length using one iteration of PBKDF2 with HMAC-SHA-256
     *
     * @param password Password bytes
     * @param salt Salt bytes
     * @param keyLength Derived Key Length in bytes requested
     * @return Derived Key bytes
     * @throws GeneralSecurityException Thrown on key derivation failures
     */
    static byte[] getDerivedKey(final byte[] password, final byte[] salt, final int keyLength) throws GeneralSecurityException {
        final char[] characters = getCharacters(password);
        final int keyLengthBits = keyLength * BIT_LENGTH_MULTIPLIER;
        final PBEKeySpec keySpec = new PBEKeySpec(characters, salt, SINGLE_ITERATION, keyLengthBits);
        final SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        final SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
        return secretKey.getEncoded();
    }

    private static char[] getCharacters(final byte[] bytes) {
        final ByteBuffer passwordBuffer = ByteBuffer.wrap(bytes);
        final CharBuffer characterBuffer = PASSPHRASE_CHARACTER_SET.decode(passwordBuffer);
        final char[] characters = new char[characterBuffer.limit()];
        characterBuffer.get(characters);
        return characters;
    }
}
