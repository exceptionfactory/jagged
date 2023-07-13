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
package com.exceptionfactory.jagged.framework.format;

import com.exceptionfactory.jagged.RecipientStanza;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Standard implementation of Recipient Stanza
 */
class StandardRecipientStanza implements RecipientStanza {
    private final String type;

    private final List<String> arguments;

    private final byte[] body;

    StandardRecipientStanza(final String type, final List<String> arguments, final byte[] body) {
        this.type = Objects.requireNonNull(type, "Type required");
        this.arguments = Collections.unmodifiableList(Objects.requireNonNull(arguments, "Arguments required"));
        this.body = Objects.requireNonNull(body, "Body required");
    }

    @Override
    public String getType() {
        return type;
    }

    @Override
    public List<String> getArguments() {
        return arguments;
    }

    @Override
    public byte[] getBody() {
        return Arrays.copyOf(body, body.length);
    }
}
