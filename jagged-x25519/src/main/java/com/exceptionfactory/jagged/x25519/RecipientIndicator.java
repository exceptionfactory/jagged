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
 * X2559 Recipient Indicators for reading and writing Recipient Stanzas
 */
enum RecipientIndicator {
    /** Bech32 Encoded Public Key Human Readable Part */
    PUBLIC_KEY_HUMAN_READABLE_PART("age"),

    /** Recipient Stanza Type */
    STANZA_TYPE("X25519"),

    /** Key Algorithm for cryptographic operations with Diffie-Hellman Key Exchange using Curve25519 */
    KEY_ALGORITHM("X25519"),

    /** HKDF-SHA-256 Key Information */
    KEY_INFORMATION("age-encryption.org/v1/X25519");

    private final String indicator;

    RecipientIndicator(final String indicator) {
        this.indicator = indicator;
    }

    public String getIndicator() {
        return indicator;
    }
}
