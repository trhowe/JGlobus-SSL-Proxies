package org.globus.gsi.jaas;

import javax.security.auth.Subject;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

/**
 * Dummy JaasSubject for testing invalid constructors
 */
class SubjectWithPrivateConstructor extends JaasSubject {

    private SubjectWithPrivateConstructor() {

    }

    @Override
    public Subject getSubject() {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Override
    public Object runAs(Subject subject, PrivilegedAction<?> action) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Override
    public Object runAs(Subject subject, PrivilegedExceptionAction<?> action) throws PrivilegedActionException {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }
}
