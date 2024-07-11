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

import com.exceptionfactory.jagged.framework.crypto.HashedDerivedKeyProducer;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.Objects;

/**
 * SSH Ed25519 implementation with HKDF-SHA-256 for deriving decryption key using marshalled Ed25519 public key
 */
class SshEd25519SharedWrapKeyProducer extends HashedDerivedKeyProducer {
    private static final byte[] KEY_INFORMATION = SshEd25519RecipientIndicator.KEY_INFORMATION.getIndicator().getBytes(StandardCharsets.UTF_8);

    private static final SshEd25519PublicKeyMarshaller PUBLIC_KEY_MARSHALLER = new SshEd25519PublicKeyMarshaller();

    /**
     * Get Derived Key using marshalled SSH Ed25519 public key with HKDF-SHA-256 and empty input key
     *
     * @param publicKey SSH Ed25519 Public Key
     * @return Wrap Cipher Key for decrypting wrapped File Key
     * @throws GeneralSecurityException Thrown on failure to derive wrap key
     */
    SshEd25519DerivedKey getDerivedKey(final PublicKey publicKey) throws GeneralSecurityException {
        Objects.requireNonNull(publicKey, "Public Key required");

        final byte[] marshalledKey = PUBLIC_KEY_MARSHALLER.getMarshalledKey(publicKey);
        final SshEd25519MarshalledKey sshEd25519MarshalledKey = new SshEd25519MarshalledKey(marshalledKey);

        final EmptyInputKey inputKey = new EmptyInputKey();
        final byte[] derivedKey = getDerivedKey(inputKey, sshEd25519MarshalledKey, KEY_INFORMATION);
        return new SshEd25519DerivedKey(derivedKey);
    }
}
