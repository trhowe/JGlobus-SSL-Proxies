package org.globus.gsi.jaas;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.Test;

import javax.security.auth.Subject;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedExceptionAction;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.FutureTask;

import static junit.framework.Assert.assertEquals;

/**
 * Created by IntelliJ IDEA.
 * User: trhowe
 * Date: Jul 15, 2010
 * Time: 2:42:27 PM
 * To change this template use File | Settings | File Templates.
 */
public class AbstractSubjectTest {
    protected static final String CRED = "testCred1";
    protected static final String CRED2 = "testCred2";

    @Before
    public void init(){

    }

    @After
    public void cleanup(){

    }

    @AfterClass
    public static void unsetJaasSubject(){
        JaasSubject.unsetCurrentSubject();
    }

    

    

    @Test
    public void testGetSubjectSameThread() throws Exception {

        Subject subject = new Subject();
        subject.getPublicCredentials().add(CRED);

        SimpleTestAction action = new SimpleTestAction();
        Subject returnedSubject =
                (Subject) JaasSubject.doAs(subject, action);

        assertEquals(subject, returnedSubject);
    }

    @Test
    public void testGetSubjectInheritThread() throws Exception {

        Subject subject = new Subject();
        subject.getPublicCredentials().add(CRED);

        ThreadTestAction action = new ThreadTestAction();
        Subject returnedSubject = (Subject) JaasSubject.doAs(subject, action);
        assertEquals(subject, returnedSubject);
        ThreadTestActionWithException exceptableAction = new ThreadTestActionWithException();
        returnedSubject = (Subject) JaasSubject.doAs(subject, exceptableAction);
        assertEquals(subject, returnedSubject);
    }

    class TestAction implements PrivilegedAction {

        Subject subject1, innerSubject, subject2;

        public Object run() {
            this.subject1 = JaasSubject.getCurrentSubject();
            this.innerSubject = AccessController.doPrivileged(new PrivilegedAction<Subject>() {
                public Subject run() {
                    return JaasSubject.getCurrentSubject();
                }
            });
            this.subject2 = JaasSubject.getCurrentSubject();
            return null;
        }
    }

    class NestedTestAction implements PrivilegedAction<Object> {

        Subject subject1, subject2;
        Subject innerSubject1, innerSubject2, innerInnerSubject;

        Subject anotherSubject;

        public NestedTestAction(Subject anotherSubject) {
            this.anotherSubject = anotherSubject;
        }

        public Object run() {
            this.subject1 = JaasSubject.getCurrentSubject();

            TestAction action = new TestAction();
            JaasSubject.doAs(anotherSubject, action);

            this.innerSubject1 = action.subject1;
            this.innerSubject2 = action.subject2;
            this.innerInnerSubject = action.innerSubject;

            this.subject2 = JaasSubject.getCurrentSubject();
            return null;
        }
    }

    class SimpleTestAction implements PrivilegedAction<Subject> {
        public Subject run() {
            return JaasSubject.getCurrentSubject();
        }
    }

    class ThreadTestAction implements PrivilegedAction<Subject> {
        ExecutorService executor = Executors.newSingleThreadExecutor();

        public Subject run() {
            AbstractSubjectTest.TestThread t = new AbstractSubjectTest.TestThread();
            FutureTask<Subject> task = new FutureTask<Subject>(t);
            executor.submit(task);
            try {
                return task.get();
            } catch (Exception e) {
                //Do Nothing
                return null;
            }
        }
    }

    class ThreadTestActionWithException implements PrivilegedExceptionAction<Subject> {
        ExecutorService executor = Executors.newSingleThreadExecutor();

        public Subject run() throws Exception {
            AbstractSubjectTest.TestThread t = new AbstractSubjectTest.TestThread();
            FutureTask<Subject> task = new FutureTask<Subject>(t);
            executor.submit(task);
            return task.get();
        }
    }

    class TestThread implements Callable<Subject> {

        public Subject call() {
            return JaasSubject.getCurrentSubject();
        }
    }
}
