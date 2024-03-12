package com.exceptionfactory.jagged.x25519;

import static com.exceptionfactory.jagged.x25519.X25519RecipientStanzaReaderFactory.newRecipientStanzaReader;
import static com.exceptionfactory.jagged.x25519.X25519RecipientStanzaWriterFactory.newRecipientStanzaWriter;
import static java.nio.channels.Channels.newChannel;
import static java.nio.channels.Channels.newInputStream;
import static java.nio.channels.Channels.newOutputStream;
import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.exceptionfactory.jagged.DecryptingChannelFactory;
import com.exceptionfactory.jagged.EncryptingChannelFactory;
import com.exceptionfactory.jagged.framework.stream.StandardDecryptingChannelFactory;
import com.exceptionfactory.jagged.framework.stream.StandardEncryptingChannelFactory;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.security.GeneralSecurityException;
import org.junit.jupiter.api.Test;

public class SimpleTest {
  private static final EncryptingChannelFactory encryptingChannelFactory =
      new StandardEncryptingChannelFactory();
  private static final DecryptingChannelFactory decryptingChannelFactory =
      new StandardDecryptingChannelFactory();

  @Test
  public void oldio() throws IOException, GeneralSecurityException {
    ByteArrayOutputStream out;
    try (ByteArrayOutputStream out1 = out = new ByteArrayOutputStream();
        WritableByteChannel out2 = newChannel(out1);
        WritableByteChannel out3 =
            encryptingChannelFactory.newEncryptingChannel(
                out2,
                singletonList(
                    newRecipientStanzaWriter(
                        "age1360h7jtlv3072kf8lq2z0jkr0l60qkyysrl9vcvm6lga7l36n52sppnvtf")));
        OutputStream out4 = newOutputStream(out3)) {
      out4.write("this is a test".getBytes());
    }
    try (ByteArrayInputStream in1 = new ByteArrayInputStream(out.toByteArray());
        ReadableByteChannel in2 = newChannel(in1);
        ReadableByteChannel in3 =
            decryptingChannelFactory.newDecryptingChannel(
                in2,
                singletonList(
                    newRecipientStanzaReader(
                        "AGE-SECRET-KEY-1RFE6TPACNNZU077UZYEZRT8980DQPQY363LN2T9HZEQX225WTZUQDJLFLJ")));
        InputStream in4 = newInputStream(in3);
        InputStreamReader in5 = new InputStreamReader(in4);
        BufferedReader in6 = new BufferedReader(in5)) {
      assertEquals("this is a test", in6.readLine());
    }
  }

  @Test
  public void oldio2() throws IOException, GeneralSecurityException {
    ByteArrayOutputStream out;
    try (OutputStream out2 =
        newOutputStream(
            encryptingChannelFactory.newEncryptingChannel(
                newChannel(out = new ByteArrayOutputStream()),
                singletonList(
                    newRecipientStanzaWriter(
                        "age1360h7jtlv3072kf8lq2z0jkr0l60qkyysrl9vcvm6lga7l36n52sppnvtf"))))) {
      out2.write("this is a test".getBytes());
    }
    try (BufferedReader in =
        new BufferedReader(
            new InputStreamReader(
                newInputStream(
                    decryptingChannelFactory.newDecryptingChannel(
                        newChannel(new ByteArrayInputStream(out.toByteArray())),
                        singletonList(
                            newRecipientStanzaReader(
                                "AGE-SECRET-KEY-1RFE6TPACNNZU077UZYEZRT8980DQPQY363LN2T9HZEQX225WTZUQDJLFLJ"))))))) {
      assertEquals("this is a test", in.readLine());
    }
  }
}
