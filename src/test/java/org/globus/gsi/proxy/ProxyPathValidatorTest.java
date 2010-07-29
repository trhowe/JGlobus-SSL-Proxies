/*
 * Copyright 1999-2010 University of Chicago
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is
 * distributed on an "AS IS" BASIS,WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */
package org.globus.gsi.proxy;

import org.globus.gsi.Certificates;

import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.globus.security.X509Credential;
import org.globus.security.util.CertificateLoadUtil;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPath;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.StringReader;
import java.security.cert.X509Certificate;
import java.security.cert.X509CRL;
import org.globus.gsi.GSIConstants;
import org.globus.gsi.TrustedCertificates;
import org.globus.gsi.SigningPolicy;
import org.globus.gsi.SigningPolicyParser;
import org.globus.gsi.CertificateRevocationLists;
import org.globus.gsi.proxy.ProxyPolicyHandler;
import org.globus.gsi.proxy.ProxyPathValidator;
import org.globus.gsi.proxy.ProxyPathValidatorException;
import org.globus.gsi.proxy.ext.ProxyCertInfo;
import org.globus.gsi.proxy.ext.ProxyPolicy;

import junit.framework.TestCase;

public class ProxyPathValidatorTest extends TestCase {
    
    public void testValidateGsi2PathGood() throws Exception {
    X509Certificate [] chain = null;

    // EEC, CA
    chain = new X509Certificate[] {Certificates.goodCertsArr[1], Certificates.goodCertsArr[0]};
    validateChain(chain, Certificates.goodCertsArr[1], false);
    
    // proxy, EEC, CA
    chain = new X509Certificate[] {Certificates.goodCertsArr[2], Certificates.goodCertsArr[1], Certificates.goodCertsArr[0]};
    validateChain(chain, Certificates.goodCertsArr[1], false);

    // limited proxy, EEC, CA
    chain = new X509Certificate[] {Certificates.goodCertsArr[3], Certificates.goodCertsArr[1], Certificates.goodCertsArr[0]};
    validateChain(chain, Certificates.goodCertsArr[1], true);

    // double limited proxy, limited proxy, EEC, CA
    chain = new X509Certificate[] {Certificates.goodCertsArr[4], Certificates.goodCertsArr[3], 
                       Certificates.goodCertsArr[1], Certificates.goodCertsArr[0]};
    
    validateChain(chain, Certificates.goodCertsArr[1], true);
    }


    private void validateChain(X509Certificate [] chain,
                   X509Certificate expectedIdentity,
                   boolean expectedLimited) 
    throws Exception {
    TestProxyPathValidator v = new TestProxyPathValidator();
    v.validate(chain); 
    assertEquals(expectedLimited, v.isLimited());
    assertEquals(expectedIdentity, v.getIdentityCertificate());
    }

    public void testValidateGsi3PathGood() throws Exception {
    X509Certificate [] chain = null;

    // GSI 3 PC impersonation, EEC, CA
    chain = new X509Certificate[] {Certificates.goodCertsArr[5], Certificates.goodCertsArr[1], Certificates.goodCertsArr[0]};
    validateChain(chain, Certificates.goodCertsArr[1], false);

    // GSI 3 PC independent, EEC, CA
    chain = new X509Certificate[] {Certificates.goodCertsArr[6], Certificates.goodCertsArr[1], Certificates.goodCertsArr[0]};
    validateChain(chain, Certificates.goodCertsArr[6], false);

    // GSI 3 PC imperson limited, EEC, CA
    chain = new X509Certificate[] {Certificates.goodCertsArr[7], Certificates.goodCertsArr[1], Certificates.goodCertsArr[0]};
    validateChain(chain, Certificates.goodCertsArr[1], true);

    // GSI 3 PC impersonation, GSI 3 PC limited impersonation, EEC, CA
    chain = new X509Certificate[] {Certificates.goodCertsArr[9], Certificates.goodCertsArr[7], 
                       Certificates.goodCertsArr[1], Certificates.goodCertsArr[0]};
    validateChain(chain, Certificates.goodCertsArr[1], true);

    // GSI 3 PC impersonation, GSI 3 PC impersonation, EEC, CA
    chain = new X509Certificate[] {Certificates.goodCertsArr[9], Certificates.goodCertsArr[5], 
                       Certificates.goodCertsArr[1], Certificates.goodCertsArr[0]};
    validateChain(chain, Certificates.goodCertsArr[1], false);

    // GSI 3 PC indepedent, GSI 3 PC independent, EEC, CA
    chain = new X509Certificate[] {Certificates.goodCertsArr[10], Certificates.goodCertsArr[6], 
                       Certificates.goodCertsArr[1], Certificates.goodCertsArr[0]};
    validateChain(chain, Certificates.goodCertsArr[10], false);

    // GSI 3 PC impersonation, GSI 3 PC independent, EEC, CA
    chain = new X509Certificate[] {Certificates.goodCertsArr[9], Certificates.goodCertsArr[6], 
                       Certificates.goodCertsArr[1], Certificates.goodCertsArr[0]};
    validateChain(chain, Certificates.goodCertsArr[6], false);

    // GSI 3 PC indepedent, GSI 3 PC limited impersonation, EEC, CA
    chain = new X509Certificate[] {Certificates.goodCertsArr[10], Certificates.goodCertsArr[7], 
                       Certificates.goodCertsArr[1], Certificates.goodCertsArr[0]};
    validateChain(chain, Certificates.goodCertsArr[10], false);
    }

    public void testValidatePathWithRestrictedProxy() throws Exception {
    X509Certificate [] chain = null;

    // GSI 3 PC restricted, EEC, CA
    chain = new X509Certificate[] {Certificates.goodCertsArr[8], Certificates.goodCertsArr[1], Certificates.goodCertsArr[0]};
    validateChain(chain, ProxyPathValidatorException.UNKNOWN_POLICY);

    // // GSI 3 PC impersonation, GSI 3 PC restricted, EEC, CA
    chain = new X509Certificate[] {Certificates.goodCertsArr[9], Certificates.goodCertsArr[8], 
                       Certificates.goodCertsArr[1], Certificates.goodCertsArr[0]};
    validateChain(chain, ProxyPathValidatorException.UNKNOWN_POLICY);

    TestProxyPathValidator v = new TestProxyPathValidator();
    v.setProxyPolicyHandler("1.3.6.1.4.1.3536.1.1.1.8", new ProxyPolicyHandler() {
        public void validate(ProxyCertInfo info, CertPath path, int index)
            throws CertPathValidatorException {
            ProxyPolicy policy = info.getProxyPolicy();
            String pol = policy.getPolicyAsString();
            assertEquals("<AllPermissions...>\r\n", pol);
        }
        });
    chain = new X509Certificate[] {Certificates.goodCertsArr[8], Certificates.goodCertsArr[1], Certificates.goodCertsArr[0]};
    v.validate(chain);
    }

    private void validateChain(X509Certificate [] chain)
    throws Exception {
    validateChain(chain, ProxyPathValidatorException.FAILURE);
    }

    private void validateChain(X509Certificate [] chain,
                   int expectedErrorCode) 
    throws Exception {
    TestProxyPathValidator v = new TestProxyPathValidator();
    try {
        v.validate(chain);
        fail("Did not throw exception as expected");
    } catch (ProxyPathValidatorException e) {
        assertEquals(expectedErrorCode, e.getErrorCode());
    }
    }

    public void testValidatePathBad() throws Exception {
    X509Certificate [] chain = null;

    // proxy, CA
    chain = new X509Certificate[] {Certificates.goodCertsArr[5], Certificates.goodCertsArr[0]};
    validateChain(chain);

    // user, proxy, CA
    chain = new X509Certificate[] {Certificates.goodCertsArr[1], Certificates.goodCertsArr[2], Certificates.goodCertsArr[0]};
    validateChain(chain);

    // user, user, CA
    chain = new X509Certificate[] {Certificates.goodCertsArr[1], Certificates.goodCertsArr[1], Certificates.goodCertsArr[0]};
    validateChain(chain);

    // user, CA, user
    chain = new X509Certificate[] {Certificates.goodCertsArr[1], Certificates.goodCertsArr[0], Certificates.goodCertsArr[1]};
    validateChain(chain);
    }
    
    public void testValidatePathMixedProxy() throws Exception {
    X509Certificate [] chain = null;

    // GSI 3 PC, GSI 2 PC, EEC, CA
    chain = new X509Certificate[] {Certificates.goodCertsArr[6], Certificates.goodCertsArr[2], 
                       Certificates.goodCertsArr[1], Certificates.goodCertsArr[0]};
    validateChain(chain);

    // GSI 2 PC, GSI 3 PC, EEC, CA
    chain = new X509Certificate[] {Certificates.goodCertsArr[2], Certificates.goodCertsArr[6], 
                       Certificates.goodCertsArr[1], Certificates.goodCertsArr[0]};
    validateChain(chain);
    }

    public void testValidatePathProxyPathConstraint() throws Exception {
    X509Certificate [] chain = null;

    // GSI 3 PC pathlen=0, GSI 3 PC, EEC, CA
    chain = new X509Certificate[] {Certificates.goodCertsArr[11], Certificates.goodCertsArr[10], 
                       Certificates.goodCertsArr[1], Certificates.goodCertsArr[0]};
    validateChain(chain,  Certificates.goodCertsArr[10], false);

    // GSI 3 PC, GSI 3 PC pathlen=0, EEC, CA
    chain = new X509Certificate[] {Certificates.goodCertsArr[10], Certificates.goodCertsArr[11], 
                       Certificates.goodCertsArr[1], Certificates.goodCertsArr[0]};
    validateChain(chain);


    // GSI 3 PC, GSI 3 PC pathlen=1, EEC, CA
    chain = new X509Certificate[] {Certificates.goodCertsArr[10], Certificates.goodCertsArr[12], 
                       Certificates.goodCertsArr[1], Certificates.goodCertsArr[0]};
    validateChain(chain,  Certificates.goodCertsArr[10], false);

    // GSI 3 PC, GSI 3 PC, GSI 3 PC pathlen=1, EEC, CA
    chain = new X509Certificate[] {Certificates.goodCertsArr[10], Certificates.goodCertsArr[9], Certificates.goodCertsArr[12], 
                       Certificates.goodCertsArr[1], Certificates.goodCertsArr[0]};
    validateChain(chain, ProxyPathValidatorException.PATH_LENGTH_EXCEEDED);
    }
    
    public void testValidatePathCAPathConstraint() throws Exception {
    X509Certificate [] chain = null;

    // should all be OK

    // EEC, CA (pathlen=0)
    chain = new X509Certificate[] {Certificates.goodCertsArr[15], Certificates.goodCertsArr[16]};
    validateChain(chain,  Certificates.goodCertsArr[15], false);

    // GSI 2 limited PC, EEC, CA (pathlen=0)
    chain = new X509Certificate[] {Certificates.goodCertsArr[3], Certificates.goodCertsArr[15], Certificates.goodCertsArr[16]};
    validateChain(chain,  Certificates.goodCertsArr[15], true);

    // GSI 3 PC, EEC, CA (pathlen=0)
    chain = new X509Certificate[] {Certificates.goodCertsArr[17], Certificates.goodCertsArr[15], Certificates.goodCertsArr[16]};
    validateChain(chain,  Certificates.goodCertsArr[15], false);

    // GSI 2 limited PC, EEC, CA (pathlen=0), CA (pathlen=2), CA (pathlen=2)
    chain = new X509Certificate[] {Certificates.goodCertsArr[3], Certificates.goodCertsArr[15], 
                       Certificates.goodCertsArr[16], Certificates.goodCertsArr[13],
                       Certificates.goodCertsArr[13]};
    validateChain(chain,  Certificates.goodCertsArr[15], true);

    // these should fail

    // EEC, CA (pathlen=0), CA (pathlen=0)
    chain = new X509Certificate[] {Certificates.goodCertsArr[15], Certificates.goodCertsArr[16], Certificates.goodCertsArr[16]};
    validateChain(chain, ProxyPathValidatorException.PATH_LENGTH_EXCEEDED);

    // GSI 2 limited PC, EEC, CA (pathlen=0), CA (pathlen=2), CA (pathlen=2), CA (pathlen=2)
    chain = new X509Certificate[] {Certificates.goodCertsArr[3], Certificates.goodCertsArr[15], 
                       Certificates.goodCertsArr[16], Certificates.goodCertsArr[13],
                       Certificates.goodCertsArr[13], Certificates.goodCertsArr[13]};
    validateChain(chain, ProxyPathValidatorException.PATH_LENGTH_EXCEEDED);

    // GSI 3 PC, GSI 3 PC pathlen=1, EEC, CA
    chain = new X509Certificate[] {Certificates.goodCertsArr[10], Certificates.goodCertsArr[12], 
                       Certificates.goodCertsArr[1], Certificates.goodCertsArr[13]};
    validateChain(chain,  Certificates.goodCertsArr[10], false);

    // GSI 3 PC, GSI 3 PC, GSI 3 PC pathlen=1, EEC, CA
    chain = new X509Certificate[] {Certificates.goodCertsArr[10], Certificates.goodCertsArr[10], Certificates.goodCertsArr[12], 
                       Certificates.goodCertsArr[1], Certificates.goodCertsArr[13]};
    validateChain(chain, ProxyPathValidatorException.PATH_LENGTH_EXCEEDED);

    // GSI 3 PC, GSI 3 PC pathlen=0, EEC, CA
    chain = new X509Certificate[] {Certificates.goodCertsArr[10], Certificates.goodCertsArr[11], 
                       Certificates.goodCertsArr[1], Certificates.goodCertsArr[13]};
    validateChain(chain,  ProxyPathValidatorException.FAILURE);
    }

     public void testValidateChain() throws Exception {
    X509Certificate [] chain = null;
    
    // everything ok chain. this also tests signing policy for the
    // credentials used to run the test, since actual proxy path
    // validator is used and not test.
    chain = X509Credential.getDefaultCredential().getCertificateChain();

    TrustedCertificates trusted = TrustedCertificates.getDefault();
    X509Certificate [] trustedCerts = trusted.getCertificates();
        SigningPolicy[] policies = trusted.getSigningPolicies();

    ProxyPathValidator v = new ProxyPathValidator();
    v.validate(chain, trustedCerts, null, policies);
    assertEquals(false, v.isLimited());
    assertEquals(chain[1], v.getIdentityCertificate());

    // unknown ca
    v.reset();
    try {
        v.validate(chain, (X509Certificate[])null, null);
    } catch (ProxyPathValidatorException e) {
        assertEquals(ProxyPathValidatorException.UNKNOWN_CA,
                         e.getErrorCode());
    }

    // issuer vs subject do not match
    chain = new X509Certificate[] {Certificates.goodCertsArr[10], Certificates.goodCertsArr[1], Certificates.goodCertsArr[0]};
    v.reset();
    try {
        v.validate(chain, new X509Certificate[] {Certificates.goodCertsArr[0]}, null,
                       policies);
    } catch (ProxyPathValidatorException e) {
        assertEquals(ProxyPathValidatorException.FAILURE, e.getErrorCode());
    }

    // proxy cert expired
    chain = new X509Certificate[] {Certificates.goodCertsArr[3], Certificates.goodCertsArr[1], Certificates.goodCertsArr[0]};
    v.reset();
    try {
        v.validate(chain, new X509Certificate[] {Certificates.goodCertsArr[0]}, null,
                       policies);
    } catch (ProxyPathValidatorException e) {
        assertEquals(ProxyPathValidatorException.FAILURE, e.getErrorCode());
    }
    }

    public void testKeyUsage() throws Exception {
    X509Certificate [] certsArr = new X509Certificate[Certificates.testCerts.length];
    for (int i=0;i<certsArr.length;i++) {
        certsArr[i] = 
        CertificateLoadUtil.loadCertificate(new ByteArrayInputStream(Certificates.testCerts[i].getBytes()));
    }

    X509Certificate [] chain = null;

    // certArr[1] - has key usage but certSign is off - but it sings proxy
    // certArr[2] - has key usage and certSing is on
    chain = new X509Certificate[] {certsArr[0], certsArr[1], certsArr[2]};
    validateChain(chain, certsArr[1], false);
    }

    public void testNoBasicConstraintsExtension() throws Exception {
    X509Certificate [] chain = null;
    // EEC, EEC, CA - that should fail
    chain = new X509Certificate[] {Certificates.goodCertsArr[1], Certificates.goodCertsArr[1], 
                                       Certificates.goodCertsArr[0]};
    validateChain(chain);
        
    TestProxyPathValidator v = new TestProxyPathValidator();
    TrustedCertificates trustedCert =
        new TrustedCertificates(new X509Certificate[] {Certificates.goodCertsArr[1]},
                                    new SigningPolicy[] { 
                                        new SigningPolicy(new X500Principal("CN=foo"), new String[]{"CN=foo"})});
    
    // this makes the PathValidator think the chain is:
    // CA, CA, CA - which is ok. irrelevant to signing policy.
    try {
        v.validate(chain, trustedCert);
    } catch (ProxyPathValidatorException e) {
        e.printStackTrace();
        fail("Unexpected exception: " + e.getMessage());
    }
    }

    // removed date validity check.
    // FIXME
    public void testCrlsChecks() throws Exception {

    X509Certificate[] chain = null;
    // chain of good certs
    chain = X509Credential.getDefaultCredential().getCertificateChain();
    ClassLoader loader = ProxyPathValidatorTest.class.getClassLoader();
    String location1 = loader.getResource(Certificates.BASE + "testca3.rpem").getPath();
    String location2 = loader.getResource(Certificates.BASE).getPath();

    CertificateRevocationLists certRevLists = CertificateRevocationLists.getCertificateRevocationLists(location1
        + ", " + location2);
    assertTrue(certRevLists != null);
    assertTrue(certRevLists.getCrls().length > 0);

    TrustedCertificates trustedCerts = TrustedCertificates.getDefault();
    X509CRL[] crls = certRevLists.getCrls();
    assertTrue(crls != null);
        ProxyPathValidator validator = new ProxyPathValidator();
    try {
        validator.validate(chain, 
                   trustedCerts.getCertificates(),
                               certRevLists,
                               trustedCerts.getSigningPolicies());
    } catch (ProxyPathValidatorException e) {
        e.printStackTrace();
        fail("Unexpected exception: " + e.getMessage());
    }

    validator.reset();

        // remove signing policy checks and validity checks
        TestProxyPathValidator tvalidator = new TestProxyPathValidator();

    // ca1 ca1user1 good chain
    chain = new X509Certificate[] {Certificates.goodCertsArr[22], Certificates.goodCertsArr[21]};
    certRevLists = CertificateRevocationLists.getCertificateRevocationLists(location1 + ", " + location2);
    assertTrue(certRevLists != null);
    assertTrue(certRevLists.getCrls().length > 0);

    try {
        tvalidator.validate(chain, new X509Certificate[] 
                {Certificates.goodCertsArr[21]}, certRevLists, 
                                trustedCerts.getSigningPolicies());
    } catch (ProxyPathValidatorException e) {
        e.printStackTrace();
        fail("Unexpected exception: " + e.getMessage());
    }

    tvalidator.reset();

    // ca1 ca1user2 good chain
    chain = new X509Certificate[] {Certificates.goodCertsArr[23], Certificates.goodCertsArr[21]};
    try {
        tvalidator.validate(chain, new X509Certificate[]
                {Certificates.goodCertsArr[21]}, certRevLists, 
                                trustedCerts.getSigningPolicies());
    } catch (ProxyPathValidatorException e) {
        e.printStackTrace();
        fail("Unexpected exception: " + e.getMessage());
    }

    tvalidator.reset();
        
    // ca2 user1 bad chain
        chain = new X509Certificate[] {Certificates.goodCertsArr[26], Certificates.goodCertsArr[25]};
    try {
        tvalidator.validate(chain, new X509Certificate[] 
                {Certificates.goodCertsArr[25]}, certRevLists,
                                trustedCerts.getSigningPolicies());
            fail("Validation did not throw exception");
    } catch (ProxyPathValidatorException crlExp) {
        assertEquals(ProxyPathValidatorException.REVOKED, 
             crlExp.getErrorCode());
    }

    tvalidator.reset();

    // ca2 user2 bad chain
        chain = new X509Certificate[] {Certificates.goodCertsArr[27], Certificates.goodCertsArr[25]};
    try {
        tvalidator.validate(chain, new X509Certificate[] 
                {Certificates.goodCertsArr[25]}, certRevLists, 
                                trustedCerts.getSigningPolicies());
        fail("Validation did not throw exception");
    } catch (ProxyPathValidatorException crlExp) {
        assertEquals(ProxyPathValidatorException.REVOKED, 
             crlExp.getErrorCode());
    }

    tvalidator.reset();

    // ca2 user3 good chain
        chain = new X509Certificate[] {Certificates.goodCertsArr[28], Certificates.goodCertsArr[25]};
    try {
        tvalidator.validate(chain, new X509Certificate[] 
                {Certificates.goodCertsArr[25]}, certRevLists,
                                trustedCerts.getSigningPolicies());
    } catch (ProxyPathValidatorException e) {
        e.printStackTrace();
        fail("Unexpected exception: " + e.getMessage());
    }
    }

    public void testSigningPolicy() throws Exception {
        
    X509Certificate [] chain = null;

        Map<X500Principal,SigningPolicy> map = new SigningPolicyParser().parse(new StringReader(Certificates.signingPolicy));
        SigningPolicy policy = map.values().iterator().next();
        assertNotNull(policy);

        TestProxyPathValidator validator = new TestProxyPathValidator(true);
        chain = new X509Certificate[] {Certificates.goodCertsArr[1], Certificates.goodCertsArr[0]};
        TrustedCertificates tc = 
            new TrustedCertificates(new X509Certificate[] { Certificates.goodCertsArr[0] },
                                    new SigningPolicy[] { policy });
        validator.validate(chain, tc);

        map = new SigningPolicyParser().parse(new StringReader(Certificates.signingPolicyViolation));
        policy = map.values().iterator().next();
        assertNotNull(policy);
        tc = new TrustedCertificates(new X509Certificate[] { Certificates.goodCertsArr[0] },
                                     new SigningPolicy[] { policy });

        boolean expOccured = false;
        try {
            validator.validate(chain, tc);
        } catch (ProxyPathValidatorException exp) {
            expOccured = true;
        assertEquals(ProxyPathValidatorException.SIGNING_POLICY_VIOLATION,
             exp.getErrorCode());
        }
        assertTrue(expOccured);        

        // COMMENT: this test fails with the new SigningPolicy
        expOccured = false;
        try {
            map = new SigningPolicyParser().parse(new StringReader(Certificates.signingPolicySansPolicy));
        } catch (IllegalArgumentException exp) {
            expOccured = true;
        }
         assertTrue(expOccured);

        validator.validate(chain, tc, null, Boolean.FALSE);
    }

    // for testing only to disable validity checking
    class TestProxyPathValidator extends ProxyPathValidator {

        boolean policyChk = false;

        TestProxyPathValidator() {
            super();
            policyChk = false;
        }

        TestProxyPathValidator(boolean checkSigningPolicy) {
            policyChk = checkSigningPolicy;
        }

    public void validate(X509Certificate [] certPath) 
        throws ProxyPathValidatorException {
        super.validate(certPath);
    }

    public void validate(X509Certificate [] certPath,
                 TrustedCertificates trustedCerts) 
        throws ProxyPathValidatorException {
        super.validate(certPath, trustedCerts);
    }

        protected void checkValidity(X509Certificate cert) 
            throws ProxyPathValidatorException {
        }

    public void validate(X509Certificate [] certPath,
                 TrustedCertificates trustedCerts,
                             CertificateRevocationLists crlsList,
                             Boolean enforceSigningPolicy)
        throws ProxyPathValidatorException {
            
        super.validate(certPath, trustedCerts, crlsList, 
                           enforceSigningPolicy);
    }
        
        protected boolean checkCRLValidity(X509CRL crl) {
            return true;
        }    
        
        // Disabling signing policy by default for testing other
        // validation pieces
        protected void checkSigningPolicy(X509Certificate certificate,
                                          TrustedCertificates trustedCerts,
                                          Boolean enforcePolicy) 
            throws ProxyPathValidatorException {
            if (policyChk) {
                super.checkSigningPolicy(certificate, trustedCerts,
                                         enforcePolicy);
            }
        }
    }
    
}
