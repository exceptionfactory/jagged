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
package com.exceptionfactory.jagged.x25519;

import java.security.PublicKey;

/**
 * Curve25519 Base Point Public Key as described in RFC 7748 Section 4.1
 */
class BasePointPublicKey implements PublicKey {
    private static final byte BASE_POINT = 9;

    private static final String FORMAT = "RAW";

    private static final byte[] BASE_POINT_PUBLIC_KEY = new byte[RecipientKeyType.X25519.getKeyLength()];

    static {
        BASE_POINT_PUBLIC_KEY[0] = BASE_POINT;
    }

    /**
     * Get algorithm returns X25519 for Key Agreement operations
     *
     * @return X25519 algorithm
     */
    @Override
    public String getAlgorithm() {
        return RecipientIndicator.KEY_ALGORITHM.getIndicator();
    }

    /**
     * Get format returns RAW
     *
     * @return RAW format
     */
    @Override
    public String getFormat() {
        return FORMAT;
    }

    /**
     * Get encoded Base Point Public Key as 32 bytes with leading 9 following RFC 7748 Section 4.1
     *
     * @return Base Point Public Key as 32 bytes
     */
    @Override
    public byte[] getEncoded() {
        return BASE_POINT_PUBLIC_KEY.clone();
    }
}
