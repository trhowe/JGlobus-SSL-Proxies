/*
 * Copyright 1999-2006 University of Chicago
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.globus.gsi.jaas;

import org.junit.Test;

import javax.security.auth.Subject;

import static junit.framework.Assert.assertEquals;

public class GlobusSubjectTest extends AbstractSubjectTest {
    @Override
    public void init() {
        JaasSubject.unsetCurrentSubject();
    }

    @Test
    public void testNestedSubject() throws Exception {

        Subject subject = new Subject();
        subject.getPublicCredentials().add(CRED);

        Subject anotherSubject = new Subject();
        anotherSubject.getPublicCredentials().add(CRED2);

        NestedTestAction action = new NestedTestAction(anotherSubject);
        JaasSubject.doAs(subject, action);

        assertEquals(subject, action.subject1);
        assertEquals(subject, action.subject2);

        assertEquals(anotherSubject, action.innerSubject1);
        assertEquals(anotherSubject, action.innerSubject2);
        assertEquals(anotherSubject, action.innerInnerSubject);
    }

@Test
    public void testSubject() throws Exception {

        Subject subject = new Subject();
        subject.getPublicCredentials().add(CRED);

        TestAction action = new TestAction();
        JaasSubject.doAs(subject, action);

        assertEquals(subject, action.subject1);
        assertEquals(subject, action.innerSubject);
        assertEquals(subject, action.subject2);
    }}
