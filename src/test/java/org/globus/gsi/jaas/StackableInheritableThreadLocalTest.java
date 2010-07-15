package org.globus.gsi.jaas;

import org.junit.Test;

import static junit.framework.Assert.assertEquals;

/**
 * Created by IntelliJ IDEA.
 * User: trhowe
 * Date: Jul 15, 2010
 * Time: 1:25:49 PM
 * To change this template use File | Settings | File Templates.
 */
public class StackableInheritableThreadLocalTest {
    StackableInheritableThreadLocal<Object> threadLocal = new StackableInheritableThreadLocal<Object>();

    @Test
    public void testEmptyStack(){
        threadLocal.push(null);
        threadLocal.pop();
        Thread thread = new Thread(new Runnable(){
            public void run() {
                assertEquals(null, threadLocal.peek());
                assertEquals(null, threadLocal.pop());
            }
        });
        thread.start();
    }
}
