package org.globus.gsi.jaas;

import org.junit.Test;

import javax.security.auth.Subject;
import java.util.Properties;

import static junit.framework.Assert.assertEquals;

public class TestStandardSubject extends AbstractSubjectTest{
    @Override
    public void init() {
        JaasSubject.unsetCurrentSubject();        
        System.setProperty("org.globus.jaas.provider", StandardSubject.class.getCanonicalName());
    }

    @Override
    public void cleanup() {
        Properties props = System.getProperties();
        props.remove("org.globus.jaas.provider");
        System.setProperties(props);
    }

    @Test
    public void testSubject() throws Exception {

        Subject subject = new Subject();
        subject.getPublicCredentials().add(CRED);

        TestAction action = new TestAction();
        JaasSubject.doAs(subject, action);

        assertEquals(subject, action.subject1);
        assertEquals(subject, action.subject2);
    }
}
