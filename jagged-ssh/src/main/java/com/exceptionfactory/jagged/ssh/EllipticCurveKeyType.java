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

/**
 * Elliptic Curve Key Type enumerates standard properties for Ed25519 and X25519 keys
 */
enum EllipticCurveKeyType {
    /** Ed25519 coordinate key of 32 bytes for twisted Edwards curve digital signature operations */
    ED25519("Ed25519", 32),

    /** Curve25519 coordinate key of 32 bytes for X25519 key agreement operations */
    X25519("X25519", 32);

    private final String algorithm;

    private final int keyLength;

    EllipticCurveKeyType(final String algorithm, final int keyLength) {
        this.algorithm = algorithm;
        this.keyLength = keyLength;
    }

    /**
     * Get algorithm name for Java Cryptography Architecture operations
     *
     * @return Algorithm name
     */
    String getAlgorithm() {
        return algorithm;
    }

    /**
     * Get key length in bytes
     *
     * @return Key length in bytes
     */
    int getKeyLength() {
        return keyLength;
    }
}
