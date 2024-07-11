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
 * SSH Ed25519 Marshalled Public Key containing marshalled SSH public key bytes
 */
final class SshEd25519MarshalledKey extends MacKey {
    /**
     * SSH Ed25519 Marshalled Public Key constructor with required key
     *
     * @param key Marshalled Key consisting of 51 bytes
     */
    SshEd25519MarshalledKey(final byte[] key) {
        super(key, SshEd25519KeyType.MARSHALLED);
    }
}
