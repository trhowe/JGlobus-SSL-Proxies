package org.globus.util;

import java.util.ListResourceBundle;

public class SampleMessageBundle_en_US extends ListResourceBundle {
    public static final String noArgsMessage = "This is a testMessage";
    public static final String messageWithArgs = "This is a testMessage with an argument: \"{0}\".";
    public static final String noArgsKey = "noArgs";
    public static final String withArgsKey = "withArgs";
    
    @Override
    protected Object[][] getContents() {
        return new Object[][]{{noArgsKey, noArgsMessage}, {withArgsKey, messageWithArgs}};
    }
}
