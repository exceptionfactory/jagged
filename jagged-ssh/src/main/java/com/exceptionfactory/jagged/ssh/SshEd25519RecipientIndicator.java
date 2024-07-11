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
 * SSH Ed25519 Recipient Indicators for reading and writing Recipient Stanzas
 */
enum SshEd25519RecipientIndicator {
    /** SSH Ed25519 Recipient Stanza Type */
    STANZA_TYPE("ssh-ed25519"),

    /** Key Information used for HKDF-SHA-256 */
    KEY_INFORMATION("age-encryption.org/v1/ssh-ed25519");

    private final String indicator;

    SshEd25519RecipientIndicator(final String indicator) {
        this.indicator = indicator;
    }

    public String getIndicator() {
        return indicator;
    }
}
