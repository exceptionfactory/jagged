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

import com.exceptionfactory.jagged.RecipientStanza;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * X25519 Recipient Stanza with standard type and single argument containing ephemeral shared public key
 */
class X25519RecipientStanza implements RecipientStanza {
    private final List<String> arguments;

    private final byte[] body;

    X25519RecipientStanza(final String ephemeralShare, final byte[] body) {
        this.arguments = Collections.singletonList(Objects.requireNonNull(ephemeralShare, "Ephemeral Share required"));
        this.body = Objects.requireNonNull(body, "Stanza Body required");
    }

    /**
     * Get Recipient Stanza Type returns X25519
     *
     * @return X25519 Type
     */
    @Override
    public String getType() {
        return RecipientIndicator.STANZA_TYPE.getIndicator();
    }

    /**
     * Get Recipient Stanza Arguments containing the ephemeral share encoded
     *
     * @return Recipient Stanza Arguments
     */
    @Override
    public List<String> getArguments() {
        return arguments;
    }

    /**
     * Get Recipient Stanza Body containing encrypted File Key with a length of 32 bytes
     *
     * @return Encrypted File Key body of 32 bytes
     */
    @Override
    public byte[] getBody() {
        return body.clone();
    }
}
