package org.globus.util;

import org.junit.Test;

import java.text.MessageFormat;

import static junit.framework.Assert.assertEquals;

public class I18nTest {

    @Test
    public void testi18n() {
        I18n i18n = I18n.getI18n(SampleMessageBundle_en_US.class.getCanonicalName());
        String message = i18n.getMessage(SampleMessageBundle_en_US.noArgsKey);
        assertEquals(SampleMessageBundle_en_US.noArgsMessage, message);
        message = i18n.getMessage(SampleMessageBundle_en_US.withArgsKey, "test");
        assertEquals(MessageFormat.format(SampleMessageBundle_en_US.messageWithArgs, "test"), message);
        i18n = I18n.getI18n(SampleMessageBundle_en_US.class.getCanonicalName(), I18nTest.class.getClassLoader());
        message = i18n.getMessage(SampleMessageBundle_en_US.noArgsKey);
        assertEquals(SampleMessageBundle_en_US.noArgsMessage, message);
        message = i18n.getMessage(SampleMessageBundle_en_US.withArgsKey, "test");
        assertEquals(MessageFormat.format(SampleMessageBundle_en_US.messageWithArgs, "test"), message);
        i18n = I18n.getI18n(SampleMessageBundle2_en_US.class.getCanonicalName(), null);
        message = i18n.getMessage(SampleMessageBundle2_en_US.noArgsKey);
        assertEquals(SampleMessageBundle2_en_US.noArgsMessage, message);
        message = i18n.getMessage(SampleMessageBundle2_en_US.withArgsKey, "test");
        assertEquals(MessageFormat.format(SampleMessageBundle2_en_US.messageWithArgs, "test"), message);
    }
}
