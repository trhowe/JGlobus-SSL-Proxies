package org.globus.gsi.jaas;

import java.util.ListResourceBundle;

public class JaasErrors_en_US extends ListResourceBundle {

    @Override
    protected Object[][] getContents() {
        return new Object[][]{{"loadError", "[JGLOBUS-72] Unable to load \"{0}\" class"},
                {"instanError", "[JGLOBUS-73] Unable to instantiate \"{0}\" class"}};
    }
}
