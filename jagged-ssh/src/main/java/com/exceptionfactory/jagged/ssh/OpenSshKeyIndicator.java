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

import java.nio.charset.StandardCharsets;

/**
 * OpenSSH Key Version 1 indicator fields
 */
enum OpenSshKeyIndicator {
    /** PEM Header */
    HEADER("-----BEGIN OPENSSH PRIVATE KEY-----"),

    /** PEM Footer */
    FOOTER("-----END OPENSSH PRIVATE KEY-----"),

    /** AUTH_MAGIC Header defined in openssh-portable/PROTOCOL.key */
    MAGIC_HEADER("openssh-key-v1\0"),

    /** Cipher Name None indicating no encryption */
    CIPHER_NAME_NONE("none");

    private final byte[] indicator;

    OpenSshKeyIndicator(final String indicator) {
        this.indicator = indicator.getBytes(StandardCharsets.UTF_8);
    }

    byte[] getIndicator() {
        return indicator.clone();
    }

    int getLength() {
        return indicator.length;
    }
}
