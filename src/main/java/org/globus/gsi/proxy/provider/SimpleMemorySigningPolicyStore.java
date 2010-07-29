package org.globus.gsi.proxy.provider;

import java.util.concurrent.ConcurrentHashMap;

import java.util.Map;
import javax.security.auth.x500.X500Principal;
import org.globus.gsi.SigningPolicy;
import org.globus.security.provider.SigningPolicyStoreException;

import org.globus.security.provider.SigningPolicyStore;

/**
 * @deprecated
 */
public class SimpleMemorySigningPolicyStore implements SigningPolicyStore {

    private Map<String, SigningPolicy> store;
    
    public SimpleMemorySigningPolicyStore(SigningPolicy[] policies) {
        store = new ConcurrentHashMap<String,SigningPolicy>();
        if (policies != null) {
            for (SigningPolicy policy : policies) {
                if (policy != null) {
                    store.put(policy.getCASubjectDN().getName(), policy);
                }
            }
        }
    }

    public SigningPolicy getSigningPolicy(X500Principal caPrincipal) throws SigningPolicyStoreException {
        return store.get(caPrincipal.getName());
    }

}
