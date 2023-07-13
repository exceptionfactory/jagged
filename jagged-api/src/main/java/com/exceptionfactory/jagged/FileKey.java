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
package com.exceptionfactory.jagged;

import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Symmetric File Key containing 16 bytes from a cryptographically secure pseudorandom number generator
 */
public final class FileKey implements SecretKey {
    private static final String ALGORITHM = "age-encryption.org";

    private static final String FORMAT = "RAW";

    private static final int KEY_LENGTH = 16;

    private static final byte ZERO = 0;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /** Destroyed status tracking */
    private final AtomicBoolean destroyed = new AtomicBoolean();

    /** Encoded key byte array */
    private final byte[] key;

    /**
     * File Key constructor generates a new key using java.util.SecureRandom.nextBytes()
     */
    public FileKey() {
        this.key = getSecureRandomKey();
    }

    /**
     * File Key constructor with required array of 16 bytes
     *
     * @param key Symmetric File Key of 16 bytes
     */
    public FileKey(final byte[] key) {
        this.key = getValidatedKey(key);
    }

    /**
     * Get File Key algorithm name for age encryption
     *
     * @return Algorithm name of age-encryption.org
     */
    @Override
    public String getAlgorithm() {
        return ALGORITHM;
    }

    /**
     * Get File Key format returns RAW indicating encoded key contains raw bytes
     *
     * @return Format name of RAW
     */
    @Override
    public String getFormat() {
        return FORMAT;
    }

    /**
     * Get File Key bytes
     *
     * @return File Key array of 16 bytes
     */
    @Override
    public byte[] getEncoded() {
        return key.clone();
    }

    /**
     * Destroy File Key so that it cannot be used for subsequent operations
     */
    @Override
    public void destroy() {
        Arrays.fill(key, ZERO);
        destroyed.set(true);
    }

    /**
     * Return destroyed status
     *
     * @return File Key destroyed status
     */
    @Override
    public boolean isDestroyed() {
        return destroyed.get();
    }

    private static byte[] getSecureRandomKey() {
        final byte[] key = new byte[KEY_LENGTH];
        SECURE_RANDOM.nextBytes(key);
        return key;
    }

    private static byte[] getValidatedKey(final byte[] key) {
        Objects.requireNonNull(key, "File Key required");
        if (key.length == KEY_LENGTH) {
            return key;
        } else {
            final String message = String.format("File Key Length [%d] not equal to required length [%d]", key.length, KEY_LENGTH);
            throw new IllegalArgumentException(message);
        }
    }
}
