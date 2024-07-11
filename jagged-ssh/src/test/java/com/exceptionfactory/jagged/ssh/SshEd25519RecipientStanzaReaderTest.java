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

import com.exceptionfactory.jagged.FileKey;
import com.exceptionfactory.jagged.RecipientStanza;
import com.exceptionfactory.jagged.UnsupportedRecipientStanzaException;
import com.exceptionfactory.jagged.framework.codec.CanonicalBase64;
import com.exceptionfactory.jagged.framework.crypto.FileKeyDecryptor;
import com.exceptionfactory.jagged.framework.crypto.FileKeyDecryptorFactory;
import com.exceptionfactory.jagged.framework.crypto.FileKeyEncryptor;
import com.exceptionfactory.jagged.framework.crypto.FileKeyEncryptorFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SshEd25519RecipientStanzaReaderTest {
    private static final String REJECTED = String.class.getSimpleName();

    private static final byte[] EMPTY_BODY = new byte[0];

    private static FileKey fileKey;

    private static Ed25519PrivateKey privateKey;

    private static Ed25519PublicKey publicKey;

    private static String publicKeyFingerprint;

    @Mock
    private RecipientStanza recipientStanza;

    private SshEd25519RecipientStanzaWriter writer;

    private SshEd25519RecipientStanzaReader reader;

    @BeforeAll
    static void setFileKey() throws GeneralSecurityException {
        fileKey = new FileKey();

        publicKey = Ed25519KeyPairProvider.getPublicKey();
        privateKey = Ed25519KeyPairProvider.getPrivateKey();

        final SshEd25519PublicKeyMarshaller publicKeyMarshaller = new SshEd25519PublicKeyMarshaller();
        final byte[] marshalledKey = publicKeyMarshaller.getMarshalledKey(publicKey);
        final PublicKeyFingerprintProducer publicKeyFingerprintProducer = new StandardPublicKeyFingerprintProducer();
        publicKeyFingerprint = publicKeyFingerprintProducer.getFingerprint(marshalledKey);
    }

    @BeforeEach
    void setReader() throws GeneralSecurityException {
        final X25519KeyPairGeneratorFactory keyPairGeneratorFactory = new X25519KeyPairGeneratorFactory();
        final X25519KeyAgreementFactory keyAgreementFactory = new X25519KeyAgreementFactory();

        final FileKeyEncryptorFactory fileKeyEncryptorFactory = new FileKeyEncryptorFactory();
        final FileKeyEncryptor fileKeyEncryptor = fileKeyEncryptorFactory.newFileKeyEncryptor();
        writer = new SshEd25519RecipientStanzaWriter(publicKey, keyPairGeneratorFactory, keyAgreementFactory, fileKeyEncryptor);

        final FileKeyDecryptorFactory fileKeyDecryptorFactory = new FileKeyDecryptorFactory();
        final FileKeyDecryptor fileKeyDecryptor = fileKeyDecryptorFactory.newFileKeyDecryptor();
        reader = new SshEd25519RecipientStanzaReader(publicKey, privateKey, keyPairGeneratorFactory, keyAgreementFactory, fileKeyDecryptor);
    }

    @Test
    void testGetFileKeyEmptyRecipientStanzas() {
        assertThrows(UnsupportedRecipientStanzaException.class, () -> reader.getFileKey(Collections.emptyList()));
    }

    @Test
    void testGetFileKeyRecipientStanzaTypeRejected()  {
        final List<RecipientStanza> stanzas = Collections.singletonList(recipientStanza);
        when(recipientStanza.getType()).thenReturn(REJECTED);

        assertThrows(UnsupportedRecipientStanzaException.class, () -> reader.getFileKey(stanzas));
    }

    @Test
    void testGetFileKeyRecipientStanzaKeyFingerprintNotFound()  {
        final List<RecipientStanza> stanzas = Collections.singletonList(recipientStanza);
        when(recipientStanza.getType()).thenReturn(SshEd25519RecipientIndicator.STANZA_TYPE.getIndicator());
        when(recipientStanza.getArguments()).thenReturn(Collections.emptyList());

        assertThrows(UnsupportedRecipientStanzaException.class, () -> reader.getFileKey(stanzas));
    }

    @Test
    void testGetFileKeyRecipientStanzaKeyFingerprintNotMatched()  {
        final List<RecipientStanza> stanzas = Collections.singletonList(recipientStanza);
        when(recipientStanza.getType()).thenReturn(SshEd25519RecipientIndicator.STANZA_TYPE.getIndicator());
        when(recipientStanza.getArguments()).thenReturn(Collections.singletonList(REJECTED));

        assertThrows(UnsupportedRecipientStanzaException.class, () -> reader.getFileKey(stanzas));
    }

    @Test
    void testGetFileKeyEphemeralShareNotFound() {
        final List<RecipientStanza> stanzas = Collections.singletonList(recipientStanza);
        when(recipientStanza.getType()).thenReturn(SshEd25519RecipientIndicator.STANZA_TYPE.getIndicator());
        when(recipientStanza.getArguments()).thenReturn(Collections.singletonList(publicKeyFingerprint));

        assertThrows(UnsupportedRecipientStanzaException.class, () -> reader.getFileKey(stanzas));
    }

    @Test
    void testGetFileKeyExtraArgumentFound() {
        final List<RecipientStanza> stanzas = Collections.singletonList(recipientStanza);
        when(recipientStanza.getType()).thenReturn(SshEd25519RecipientIndicator.STANZA_TYPE.getIndicator());
        when(recipientStanza.getArguments()).thenReturn(Arrays.asList(publicKeyFingerprint, REJECTED, REJECTED));

        assertThrows(UnsupportedRecipientStanzaException.class, () -> reader.getFileKey(stanzas));
    }

    @Test
    void testGetFileKeyEphemeralShareLengthNotMatched() {
        final List<RecipientStanza> stanzas = Collections.singletonList(recipientStanza);
        when(recipientStanza.getType()).thenReturn(SshEd25519RecipientIndicator.STANZA_TYPE.getIndicator());
        when(recipientStanza.getArguments()).thenReturn(Arrays.asList(publicKeyFingerprint, REJECTED));

        assertThrows(UnsupportedRecipientStanzaException.class, () -> reader.getFileKey(stanzas));
    }

    @Test
    void testGetFileKeyBodyEmpty() {
        final List<RecipientStanza> stanzas = Collections.singletonList(recipientStanza);
        when(recipientStanza.getType()).thenReturn(SshEd25519RecipientIndicator.STANZA_TYPE.getIndicator());

        final String ephemeralShare = CanonicalBase64.getEncoder().encodeToString(publicKey.getEncoded());

        when(recipientStanza.getArguments()).thenReturn(Arrays.asList(publicKeyFingerprint, ephemeralShare));
        when(recipientStanza.getBody()).thenReturn(EMPTY_BODY);

        assertThrows(UnsupportedRecipientStanzaException.class, () -> reader.getFileKey(stanzas));
    }

    @Test
    void testGetFileKey() throws GeneralSecurityException {
        final Iterable<RecipientStanza> recipientStanzas = writer.getRecipientStanzas(fileKey);

        assertNotNull(recipientStanzas);

        final FileKey fileKeyRead = reader.getFileKey(recipientStanzas);

        assertNotNull(fileKeyRead);
        assertArrayEquals(fileKey.getEncoded(), fileKeyRead.getEncoded());
    }
}
