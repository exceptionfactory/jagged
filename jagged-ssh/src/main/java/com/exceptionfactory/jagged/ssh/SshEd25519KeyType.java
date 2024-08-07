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
package com.exceptionfactory.jagged.ssh;

import com.exceptionfactory.jagged.framework.crypto.CryptographicKeyDescription;

/**
 * SSH Ed25519 Key Type references for construction and validation
 */
enum SshEd25519KeyType implements CryptographicKeyDescription {
    /** Derived Secret Key */
    DERIVED(32),

    /** Empty Input Key for HKDF-SHA-256 */
    EMPTY(0),

    /** Marshalled Public Key */
    MARSHALLED(51);

    private final int keyLength;

    SshEd25519KeyType(final int keyLength) {
        this.keyLength = keyLength;
    }

    /**
     * Get key length in bytes
     *
     * @return Key length in bytes
     */
    @Override
    public int getKeyLength() {
        return keyLength;
    }
}
