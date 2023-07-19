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
package com.exceptionfactory.jagged.framework.stream;

/**
 * STREAM Chunk Size definitions according to age-encryption Payload section
 */
enum ChunkSize {
    /** Encrypted chunk size including ChaCha20-Poly1305 tag */
    ENCRYPTED(65552),

    /** Plain chunk size before encryption and after decryption */
    PLAIN(65536);

    private final int size;

    ChunkSize(final int size) {
        this.size = size;
    }

    /**
     * Get chunk size in bytes
     *
     * @return Chunk size in bytes
     */
    public int getSize() {
        return size;
    }
}
