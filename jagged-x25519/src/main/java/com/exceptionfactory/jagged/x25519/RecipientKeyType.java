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

/**
 * Recipient Key Type enumerates standard properties for X25519 keys
 */
enum RecipientKeyType {
    /** Curve25519 coordinate key of 32 bytes for X25519 key agreement operations */
    X25519(32);

    private final int keyLength;

    RecipientKeyType(final int keyLength) {
        this.keyLength = keyLength;
    }

    /**
     * Get key length in bytes
     *
     * @return Key length in bytes
     */
    public int getKeyLength() {
        return keyLength;
    }
}
