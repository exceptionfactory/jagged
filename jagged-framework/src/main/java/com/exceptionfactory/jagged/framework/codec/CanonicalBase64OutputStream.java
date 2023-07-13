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
package com.exceptionfactory.jagged.framework.codec;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Base64;
import java.util.Objects;

/**
 * Canonical Base64 wrapping Output Stream writes line feed characters after 64 characters
 */
public class CanonicalBase64OutputStream extends FilterOutputStream {
    private static final int LINE_FEED = 10;

    private static final int MAXIMUM_LINE_LENGTH = 64;

    private static final int EMPTY_LINE_LENGTH = 0;

    private static final Base64.Encoder ENCODER = Base64.getEncoder().withoutPadding();

    /**
     * Canonical Base64 Output Stream constructor wraps an Output Stream for subsequent encoding
     *
     * @param outputStream Output Stream wrapped for Base64 encoding
     */
    public CanonicalBase64OutputStream(final OutputStream outputStream) {
        super(ENCODER.wrap(new LineEncodingOutputStream(Objects.requireNonNull(outputStream, "Output Stream required"))));
    }

    private static final class LineEncodingOutputStream extends FilterOutputStream {
        private int lineLength = EMPTY_LINE_LENGTH;

        private LineEncodingOutputStream(final OutputStream outputStream) {
            super(outputStream);
        }

        /**
         * Write byte code and write line feed character when line length reached
         *
         * @param code Byte code to be written
         * @throws IOException Thrown on failures to write byte codes
         */
        @Override
        public void write(final int code) throws IOException {
            super.write(code);
            lineLength++;
            if (lineLength == MAXIMUM_LINE_LENGTH) {
                super.write(LINE_FEED);
                lineLength = EMPTY_LINE_LENGTH;
            }
        }
    }
}
