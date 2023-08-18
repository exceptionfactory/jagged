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
package com.exceptionfactory.jagged.framework.crypto;

import java.security.Provider;
import java.util.Objects;

/**
 * Factory abstraction for instances of File Key Encryptor
 */
public final class FileKeyEncryptorFactory {
    private final Provider provider;

    /**
     * File Key Encryptor Factory uses the system default Security Provider configuration
     */
    public FileKeyEncryptorFactory() {
        provider = null;
    }

    /**
     * File Key Encryptor Factory with support for custom Security Provider
     *
     * @param provider Security Provider supporting ChaCha20-Poly1305
     */
    public FileKeyEncryptorFactory(final Provider provider) {
        this.provider = Objects.requireNonNull(provider, "Provider required");
    }

    /**
     * Create new instance of File Key Encryptor using current configuration
     *
     * @return File Key Encryptor
     */
    public FileKeyEncryptor newFileKeyEncryptor() {
        return provider == null ? new StandardFileKeyEncryptor() : new StandardFileKeyEncryptor(provider);
    }
}
