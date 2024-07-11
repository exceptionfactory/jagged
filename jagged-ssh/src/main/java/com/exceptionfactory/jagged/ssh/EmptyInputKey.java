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

import com.exceptionfactory.jagged.framework.crypto.MacKey;

/**
 * Empty Input Key extension of Message Authentication Code Key for HKDF from salt key
 */
final class EmptyInputKey extends MacKey {
    private static final byte[] EMPTY = new byte[]{};

    /**
     * Empty Input Key constructor
     *
     */
    EmptyInputKey() {
        super(EMPTY, SshEd25519KeyType.EMPTY);
    }
}
