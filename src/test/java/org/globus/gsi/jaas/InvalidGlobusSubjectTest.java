package org.globus.gsi.jaas;

import org.junit.Test;

import java.util.List;
import java.util.Properties;

import static org.junit.Assert.fail;


public class InvalidGlobusSubjectTest {

    @Test
    public void testInvalidSubject() throws Exception {
        Properties props = System.getProperties();
        props.put("org.globus.jaas.provider", List.class.getCanonicalName());
        System.setProperties(props);
        try {
            JaasSubject.getJaasSubject();
            System.out.println(System.getProperty("org.globus.jaas.provider"));
            fail();
        } catch (RuntimeException e) {
            System.out.println(e.getMessage());
        }
        System.setProperty("org.globus.jaas.provider", "org.globus.gsi.jaas.NonexistentProvider");
        try {
            JaasSubject.getJaasSubject();
            fail();
        } catch (RuntimeException e) {
            e.printStackTrace();
            assert (e.getCause() instanceof ClassNotFoundException);
       }
        System.setProperty("org.globus.jaas.provider", SubjectWithBadConstructor.class.getCanonicalName());
        try {
            JaasSubject.getJaasSubject();
            fail();
        } catch (RuntimeException e) {
            e.printStackTrace();
            assert (e.getCause() instanceof InstantiationException);
        }
        System.setProperty("org.globus.jaas.provider", SubjectWithPrivateConstructor.class.getCanonicalName());
        try {
            JaasSubject.getJaasSubject();
            fail();
        } catch (RuntimeException e) {
            e.printStackTrace();
            assert (e.getCause() instanceof IllegalAccessException);
        }
        props = System.getProperties();
        props.remove("org.globus.jaas.provider");
        System.setProperties(props);

    }


}
