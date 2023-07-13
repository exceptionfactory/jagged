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
package com.exceptionfactory.jagged.scrypt;

import com.exceptionfactory.jagged.RecipientStanza;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * scrypt Recipient Stanza with standard type and arguments containing encoded salt and work factor
 */
class ScryptRecipientStanza implements RecipientStanza {
    private final List<String> arguments;

    private final byte[] body;

    ScryptRecipientStanza(final String saltEncoded, final int workFactor, final byte[] body) {
        Objects.requireNonNull(saltEncoded, "Salt required");
        this.arguments = Collections.unmodifiableList(Arrays.asList(saltEncoded, Integer.toString(workFactor)));
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
