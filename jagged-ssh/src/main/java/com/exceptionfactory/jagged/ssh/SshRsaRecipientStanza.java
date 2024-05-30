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

import com.exceptionfactory.jagged.RecipientStanza;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * SSH RSA Recipient Stanza with standard type and arguments containing encoded public key fingerprint
 */
class SshRsaRecipientStanza implements RecipientStanza {
    private final List<String> arguments;

    private final byte[] body;

    SshRsaRecipientStanza(final String keyFingerprint, final byte[] body) {
        Objects.requireNonNull(keyFingerprint, "Key fingerprint required");
        this.arguments = Collections.singletonList(keyFingerprint);
        this.body = Objects.requireNonNull(body, "Stanza Body required");
    }

    /**
     * Get Recipient Stanza Type returns ssh-rsa
     *
     * @return SSH RSA Type
     */
    @Override
    public String getType() {
        return SshRsaRecipientIndicator.STANZA_TYPE.getIndicator();
    }

    /**
     * Get Recipient Stanza Arguments containing the key fingerprint
     *
     * @return Recipient Stanza Arguments
     */
    @Override
    public List<String> getArguments() {
        return arguments;
    }

    /**
     * Get Recipient Stanza Body containing encrypted File Key
     *
     * @return Encrypted File Key body
     */
    @Override
    public byte[] getBody() {
        return body.clone();
    }
}
