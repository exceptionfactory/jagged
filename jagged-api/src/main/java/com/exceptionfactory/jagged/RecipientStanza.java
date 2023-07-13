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
package com.exceptionfactory.jagged;

import java.util.List;

/**
 * Recipient Stanza describes a section of the age header encapsulating the information required to derive a File Key
 */
public interface RecipientStanza {
    /**
     * Get Recipient Stanza Type returns the first argument from the header section
     *
     * @return Recipient Stanza Type
     */
    String getType();

    /**
     * Get zero or more Recipient Stanza arguments located after the Stanza Type in the header section
     *
     * @return Recipient Stanza Arguments
     */
    List<String> getArguments();

    /**
     * Get Recipient Stanza Body decoded from Base64 representation in header section
     *
     * @return Recipient Stanza Body
     */
    byte[] getBody();
}
