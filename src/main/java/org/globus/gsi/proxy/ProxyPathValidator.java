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


import java.security.Security;

import java.util.HashMap;
import org.globus.security.trustmanager.X509ProxyCertPathValidator;
import org.globus.security.X509ProxyCertPathParameters;
import java.security.KeyStore;
import java.security.cert.CertStore;
import org.globus.gsi.proxy.provider.SimpleMemorySigningPolicyStore;
import org.globus.gsi.proxy.provider.SimpleMemoryProvider;
import java.util.Map;
import org.globus.gsi.proxy.provider.SimpleMemoryCertStoreParams;
import org.globus.gsi.proxy.provider.SimpleMemoryKeyStoreLoadStoreParameter;
import org.globus.security.util.ProxyCertificateUtil;
import org.globus.security.util.CertificateLoadUtil;
import org.globus.security.util.CertificateUtil;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import org.globus.common.CoGProperties;
import java.util.Enumeration;
import java.util.Vector;
import java.util.Date;
import java.util.Hashtable;
import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateExpiredException;
import java.security.GeneralSecurityException;
import java.security.cert.X509CRL;
import org.globus.gsi.GSIConstants;
import org.globus.gsi.TrustedCertificates;
import org.globus.gsi.SigningPolicy;
import org.globus.gsi.CertificateRevocationLists;
import org.globus.gsi.bc.BouncyCastleUtil;
import org.globus.gsi.ptls.PureTLSUtil;
import org.globus.gsi.proxy.ext.ProxyCertInfo;
import org.globus.gsi.proxy.ext.ProxyPolicy;
import org.globus.util.I18n;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.BasicConstraints;
import COM.claymoresystems.sslg.CertVerifyPolicyInt;
import COM.claymoresystems.cert.X509Cert;
import COM.claymoresystems.cert.CertContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Performs certificate/proxy path validation. It supports both old
 * style Globus proxy as well as the new proxy certificate format.  It
 * checks BasicConstraints, KeyUsage, and ProxyCertInfo (if
 * applicable) extensions. It also checks for presence in CRLs and
 * signing policy compliance. This validator requires that each CA be
 * installed with signing policy. It also provides a callback interface
 * for custom policy checking of restricted proxies. <BR> Currently,
 * does <B>not</B> perform the following checks for the new proxy
 * certificates: <OL> <LI> Check if proxy serial number is unique (and
 * the version number) <LI> Check for empty subject names </OL>
 */

public class ProxyPathValidator {

    static {
        Security.addProvider(new SimpleMemoryProvider());
    }
    
    private static I18n i18n =
            I18n.getI18n("org.globus.gsi.proxy.errors",
                         ProxyPathValidator.class.getClassLoader());

    private static Log logger = 
    LogFactory.getLog(ProxyPathValidator.class.getName());

    private boolean rejectLimitedProxyCheck = false;
    private boolean limited = false;
    private X509Certificate identityCert = null;
    private Hashtable proxyPolicyHandlers = null;

    /**
     * Returns if the validated proxy path is limited. A proxy path
     * is limited when a limited proxy is present anywhere after the
     * first non-impersonation proxy certificate.
     *
     * @return true if the validated path is limited
     */
    public boolean isLimited() {
    return this.limited;
    }
    
    /**
     * Returns the identity certificate. The first certificates in the
     * path that is not an impersonation proxy, e.g. it could be a
     * restricted proxy or end-entity certificate
     *
     * @return <code>X509Certificate</code> the identity certificate
     */
    public X509Certificate getIdentityCertificate() {
    return this.identityCert;
    }

    /**
     * Returns the subject name of the identity certificate (in the
     * Globus format) 
     * @see #getIdentityCertificate
     * @return the subject name of the identity certificate in the 
     *         Globus format
     */
    public String getIdentity() {
    return BouncyCastleUtil.getIdentity(this.identityCert);
    }

    /**
     * Removes a restricted proxy policy handler.
     *
     * @param id the Oid of the policy handler to remove.
     * @return <code>ProxyPolicyHandler</code> the removed handler, or 
     *         null if there is no handler registered under that
     *         id.
     */
    public ProxyPolicyHandler removeProxyPolicyHandler(String id) {
    return (id != null && this.proxyPolicyHandlers != null) ?
        (ProxyPolicyHandler)this.proxyPolicyHandlers.remove(id) :
        null;
    }

    /**
     * Sets a restricted proxy policy handler.
     * 
     * @param id the Oid of the proxy policy to install the handler for.
     * @param handler the proxy policy handler.
     * @return <code>ProxyPolicyHandler</code> the previous handler 
     *        installed under the specified id. Usually, will be null.
     */
    public ProxyPolicyHandler setProxyPolicyHandler(String id, 
                            ProxyPolicyHandler handler) {
    if (id == null) {
        throw new IllegalArgumentException(i18n.getMessage("proxyPolicyId"));
    }
    if (handler == null) {
        throw new IllegalArgumentException(i18n.
                getMessage("proxyPolicyHandler"));
    }
    if (this.proxyPolicyHandlers == null) {
        this.proxyPolicyHandlers = new Hashtable();
    }
    return (ProxyPolicyHandler)this.proxyPolicyHandlers.put(id, handler);
    }

    /**
     * Retrieves a restricted proxy policy handler for a given policy id.
     *
     * @param id the Oid of the proxy policy to get the handler for.
     * @return <code>ProxyPolicyHandler</code> the policy handler
     *         registered for the given id or null if none is 
     *         registered.
     */
    public ProxyPolicyHandler getProxyPolicyHandler(String id) {
    return (id != null && this.proxyPolicyHandlers != null) ?
        (ProxyPolicyHandler)this.proxyPolicyHandlers.get(id) :
        null;
    }

    /**
     * Resets the internal state. Useful for reusing the same
     * instance for validating multiple certificate paths.
     */
    public void reset() {
    this.rejectLimitedProxyCheck= false;
    this.limited = false;
    this.identityCert = null;
    }
    
    /**
     * If set, the validate rejects certificate chain if limited proxy if found
     */
    public void setRejectLimitedProxyCheck(boolean rejectLimProxy) {
    this.rejectLimitedProxyCheck = rejectLimProxy;
    }
        
    /**
     * Performs <B>all</B> certificate path validation including
     * checking of the signatures, validity of the certificates, 
     * extension checking, etc.<BR>
     * It uses the PureTLS code to do basic cert signature checking
     * checking and then calls {@link #validate(X509Certificate[],
     * TrustedCertificates) validate} for further checks.
     * 
     * @param certPath the certificate path to validate.
     * @param trustedCerts the trusted (CA) certificates.
     * @exception ProxyPathValidatorException if certificate
     *            path validation fails.
     */
    public void validate(X509Certificate[] certPath, 
             X509Certificate[] trustedCerts)
    throws ProxyPathValidatorException {
    validate(certPath, trustedCerts, null);
    }

    public void validate(X509Certificate[] certPath, 
             X509Certificate[] trustedCerts,
             CertificateRevocationLists crls)
    throws ProxyPathValidatorException {
        validate(certPath, trustedCerts, crls, null);
    }

    public void validate(X509Certificate[] certPath, 
             X509Certificate[] trustedCerts,
                         CertificateRevocationLists crls,
                         SigningPolicy[] signingPolicies)
    throws ProxyPathValidatorException {
    
        validate(certPath, trustedCerts, crls, signingPolicies, null);
    }
    
    public void validate(X509Certificate[] certPath, 
             X509Certificate[] trustedCerts,
             CertificateRevocationLists crls, 
                         SigningPolicy[] signingPolicies,
                         Boolean enforceSigningPolicy)
    throws ProxyPathValidatorException {

    if (certPath == null) {
        throw new IllegalArgumentException(i18n.getMessage("certsNull"));
    }

        // If trusted certificates is not null, but signing policy is,
        // then this might fail down the line.
    TrustedCertificates trustedCertificates = null;
    if (trustedCerts != null) {
        trustedCertificates = new TrustedCertificates(trustedCerts,
                                                          signingPolicies);
    }
        
    validate(certPath, trustedCertificates, crls, enforceSigningPolicy);
    }

    /**
     * Performs certificate path validation. Does <B>not</B> check
     * the cert signatures but it performs all other checks like 
     * the extension checking, validity checking, restricted policy
     * checking, CRL checking, etc.
     * 
     * @param certPath the certificate path to validate.
     * @exception ProxyPathValidatorException if certificate
     *            path validation fails.
     */
    protected void validate(X509Certificate [] certPath) 
    throws ProxyPathValidatorException {
    validate(certPath, 
         (TrustedCertificates)null, 
         (CertificateRevocationLists)null);
    }

    /**
     * Performs certificate path validation. Does <B>not</B> check
     * the cert signatures but it performs all other checks like 
     * the extension checking, validity checking, restricted policy
     * checking, CRL checking, etc.
     * 
     * @param certPath the certificate path to validate.
     * @param trustedCerts the trusted (CA) certificates. If null, 
     *            the default trusted certificates will be used.
     * @exception ProxyPathValidatorException if certificate
     *            path validation fails.
     */
    protected void validate(X509Certificate [] certPath,
                TrustedCertificates trustedCerts)
    throws ProxyPathValidatorException {
    validate(certPath, trustedCerts, null);
    }
    
    protected void validate(X509Certificate [] certPath,
                TrustedCertificates trustedCerts,
                CertificateRevocationLists crlsList) 
    throws ProxyPathValidatorException {

    validate(certPath, trustedCerts, crlsList, null);
    }

    /**
     * Performs certificate path validation. Does <B>not</B> check
     * the cert signatures but it performs all other checks like 
     * the extension checking, validity checking, restricted policy
     * checking, CRL checking, etc.
     * 
     * @param certPath the certificate path to validate.
     * @param trustedCerts the trusted (CA) certificates. If null, 
     *            the default trusted certificates will be used.
     * @param crlsList the certificate revocation list. If null, 
     *            the default certificate revocation list will be used.
     * @exception ProxyPathValidatorException if certificate
     *            path validation fails.
     */
    protected void validate(X509Certificate [] certPath,
                TrustedCertificates trustedCerts,
                CertificateRevocationLists crlsList,
                Boolean enforceSigningPolicy)
    throws ProxyPathValidatorException {
    
        if (certPath == null) {
            throw new IllegalArgumentException(i18n.getMessage("certsNull"));
        }

        if (crlsList == null) {
            crlsList = CertificateRevocationLists.getDefaultCertificateRevocationLists();
        }

        if (trustedCerts == null) {
            trustedCerts = TrustedCertificates.getDefault();
        }

        try {
           SimpleMemoryKeyStoreLoadStoreParameter ksParams = new SimpleMemoryKeyStoreLoadStoreParameter();
           SimpleMemoryCertStoreParams csParams = new SimpleMemoryCertStoreParams(null, crlsList.getCrls());
           ksParams.setCerts(trustedCerts.getCertificates());
           Map<String,ProxyPolicyHandler> initHandlers = new HashMap<String,ProxyPolicyHandler>();
           if (this.proxyPolicyHandlers != null) {
               initHandlers.putAll(proxyPolicyHandlers);
           }
           KeyStore ks = KeyStore.getInstance(SimpleMemoryProvider.KEYSTORE_TYPE, SimpleMemoryProvider.PROVIDER_NAME);
           CertStore cs = CertStore.getInstance(SimpleMemoryProvider.CERTSTORE_TYPE, csParams, SimpleMemoryProvider.PROVIDER_NAME);
           SimpleMemorySigningPolicyStore spStore = new SimpleMemorySigningPolicyStore(trustedCerts.getSigningPolicies());
           ks.load(ksParams);
           X509ProxyCertPathParameters params = new X509ProxyCertPathParameters(ks, cs,
               spStore, this.rejectLimitedProxyCheck, initHandlers);
           X509ProxyCertPathValidator validator = new X509ProxyCertPathValidator();
           validator.engineValidate(CertificateUtil.getCertPath(certPath), params);
           this.identityCert = validator.getIdentityCertificate();
        } catch (Exception e) {
            // XXX: just a hack for now
            throw new ProxyPathValidatorException(ProxyPathValidatorException.FAILURE, e);
        }
    }

    protected void checkIdentity(X509Certificate cert, int certType) 
    throws ProxyPathValidatorException {
    
    if (this.identityCert == null) {
        // check if limited
        if (ProxyCertificateUtil.isLimitedProxy(certType)) {
        this.limited = true;

        if (this.rejectLimitedProxyCheck) {
            throw new ProxyPathValidatorException(
              ProxyPathValidatorException.LIMITED_PROXY_ERROR, 
              cert,
              i18n.getMessage("limitedProxy"));
        }
        }

        // set the identity cert
        if (!ProxyCertificateUtil.isImpersonationProxy(certType)) {
        this.identityCert = cert;
        }
    }
    }

    protected void checkRestrictedProxy(TBSCertificateStructure proxy,
                    X509Certificate[] certPath,
                    int index) 
    throws ProxyPathValidatorException, IOException, CertificateException, CertPathValidatorException {
    
    logger.debug("enter: checkRestrictedProxy");

    ProxyCertInfo info = BouncyCastleUtil.getProxyCertInfo(proxy);

    // just a sanity check
    if (info == null) {
         throw new ProxyPathValidatorException(
           ProxyPathValidatorException.FAILURE,
           certPath[index],
           i18n.getMessage("proxyErr07"));
    }

    ProxyPolicy policy = info.getProxyPolicy();

    // another sanity check
    if (policy == null) {
        throw new ProxyPathValidatorException(
           ProxyPathValidatorException.FAILURE,
           certPath[index],
           i18n.getMessage("proxyErr08"));
    }

    String pl = policy.getPolicyLanguage().getId();

    ProxyPolicyHandler handler = getProxyPolicyHandler(pl);

    if (handler == null) {
         throw new ProxyPathValidatorException(
           ProxyPathValidatorException.UNKNOWN_POLICY,
           certPath[index],
           i18n.getMessage("proxyErr09", pl));
    }

    handler.validate(info, CertificateUtil.getCertPath(certPath), index);

    logger.debug("exit: checkRestrictedProxy");
    
    }
    
    protected void checkKeyUsage(TBSCertificateStructure issuer,
                 X509Certificate[] certPath,
                 int index) 
    throws ProxyPathValidatorException, IOException {

    logger.debug("enter: checkKeyUsage");

    boolean[] issuerKeyUsage = getKeyUsage(issuer);
    if (issuerKeyUsage != null) {
        if (!issuerKeyUsage[5]) {
        throw new ProxyPathValidatorException(
            ProxyPathValidatorException.FAILURE,
            certPath[index],
            i18n.getMessage("proxyErr10"));
        }
    }
    
    logger.debug("exit: checkKeyUsage");
    }

    // ok
    protected void checkProxyConstraints(TBSCertificateStructure proxy,
                     TBSCertificateStructure issuer,
                     X509Certificate checkedProxy)
    throws ProxyPathValidatorException, IOException {

    logger.debug("enter: checkProxyConstraints");

    X509Extensions extensions;
    DERObjectIdentifier oid;
    X509Extension ext;

    X509Extension proxyKeyUsage = null;
    
    extensions = proxy.getExtensions();
    if (extensions != null) {
        Enumeration e = extensions.oids();
        while (e.hasMoreElements()) {
        oid = (DERObjectIdentifier)e.nextElement();
        ext = extensions.getExtension(oid);
        if (oid.equals(X509Extensions.SubjectAlternativeName) ||
            oid.equals(X509Extensions.IssuerAlternativeName)) {
            // No Alt name extensions - 3.2 & 3.5
            throw new ProxyPathValidatorException(
              ProxyPathValidatorException.PROXY_VIOLATION,
              checkedProxy,
              i18n.getMessage("proxyErr11"));
        } else if (oid.equals(X509Extensions.BasicConstraints)) {
            // Basic Constraint must not be true - 3.8
            BasicConstraints basicExt = BouncyCastleUtil.getBasicConstraints(ext);
            if (basicExt.isCA()) {
            throw new ProxyPathValidatorException(
                  ProxyPathValidatorException.PROXY_VIOLATION,
                  checkedProxy,
                  i18n.getMessage("proxyErr12"));
            }
        } else if (oid.equals(X509Extensions.KeyUsage)) {
            proxyKeyUsage = ext;

            boolean[] keyUsage = BouncyCastleUtil.getKeyUsage(ext);
            // these must not be asserted
            if (keyUsage[1] ||
            keyUsage[5]) {
            throw new ProxyPathValidatorException(
                  ProxyPathValidatorException.PROXY_VIOLATION,
                  checkedProxy,
                  i18n.getMessage("proxyErr13"));
            }
        }
        }
    }
    
    extensions = issuer.getExtensions();

    if (extensions != null) {
        Enumeration e = extensions.oids();
        while (e.hasMoreElements()) {
        oid = (DERObjectIdentifier)e.nextElement();
        ext = extensions.getExtension(oid);
        if (oid.equals(X509Extensions.KeyUsage)) {
            // If issuer has it then proxy must have it also
            if (proxyKeyUsage == null) {
            throw new ProxyPathValidatorException(
                      ProxyPathValidatorException.PROXY_VIOLATION,
                      checkedProxy,
                      i18n.getMessage("proxyErr14"));
            }
            // If issuer has it as critical so does the proxy
            if (ext.isCritical() && !proxyKeyUsage.isCritical()) {
            throw new ProxyPathValidatorException(
                      ProxyPathValidatorException.PROXY_VIOLATION,
                      checkedProxy,
                      i18n.getMessage("proxy15"));
            }
        }
        }
    }

    logger.debug("exit: checkProxyConstraints");
    }
    
    // ok
    protected void 
        checkUnsupportedCriticalExtensions(TBSCertificateStructure crt,
                                           int certType,
                                           X509Certificate checkedProxy) 
    throws ProxyPathValidatorException {
    
    logger.debug("enter: checkUnsupportedCriticalExtensions");

    X509Extensions extensions = crt.getExtensions();
    if (extensions != null) {
        Enumeration e = extensions.oids();
        while (e.hasMoreElements()) {
        DERObjectIdentifier oid = (DERObjectIdentifier)e.nextElement();
        X509Extension ext = extensions.getExtension(oid);
        if (ext.isCritical()) {
            if (oid.equals(X509Extensions.BasicConstraints) ||
            oid.equals(X509Extensions.KeyUsage) ||
            (oid.equals(ProxyCertInfo.OID) && 
                    ProxyCertificateUtil.isGsi4Proxy(certType)) ||
            (oid.equals(ProxyCertInfo.OLD_OID) && 
                    ProxyCertificateUtil.isGsi3Proxy(certType))) {
            } else {
            throw new ProxyPathValidatorException(
                  ProxyPathValidatorException
                              .UNSUPPORTED_EXTENSION,
                  checkedProxy,
                  i18n.getMessage("proxyErr16", oid.getId()));
            }
        }
        }
    }

    logger.debug("exit: checkUnsupportedCriticalExtensions");
    }
    
    protected void checkValidity(X509Certificate cert) 
    throws ProxyPathValidatorException {

    try {
        cert.checkValidity();
    } catch (CertificateExpiredException e) {

            String msg = i18n.getMessage("proxyErr17", new Object[] {
                cert.getSubjectDN().getName(), 
                ProxyPathValidatorException.getDateAsString(cert
                                                            .getNotAfter()), 
                ProxyPathValidatorException.getDateAsString(new Date()) });
        throw new ProxyPathValidatorException(ProxyPathValidatorException
                                                  .FAILURE, cert, msg);
    } catch (CertificateNotYetValidException e) {
            Date date = new Date();
            String msg = i18n.getMessage("proxyErr18", new Object[] {
                cert.getSubjectDN().getName(), ProxyPathValidatorException
                .getDateAsString(cert.getNotBefore()), 
                ProxyPathValidatorException.getDateAsString(new Date())}); 
        throw new ProxyPathValidatorException(ProxyPathValidatorException
                                                  .FAILURE, cert, msg);
    }
    }

    protected int getCAPathConstraint(TBSCertificateStructure crt) 
    throws IOException {
    X509Extensions extensions = crt.getExtensions();
    if (extensions == null) {
        return -1;
    }
    X509Extension ext =
        extensions.getExtension(X509Extensions.BasicConstraints);
    if (ext != null) {
        BasicConstraints basicExt = BouncyCastleUtil.getBasicConstraints(ext);
        if (basicExt.isCA()) {
        BigInteger pathLen = basicExt.getPathLenConstraint();
        return (pathLen == null) ? Integer.MAX_VALUE : pathLen.intValue();
        } else {
        return -1;
        }
    }
    return -1;
    }

    protected boolean[] getKeyUsage(TBSCertificateStructure crt) 
    throws IOException {
    X509Extensions extensions = crt.getExtensions();
    if (extensions == null) {
        return null;
    }
    X509Extension ext =
        extensions.getExtension(X509Extensions.KeyUsage);
    return (ext != null) ? BouncyCastleUtil.getKeyUsage(ext) : null;
    }

    // checkCRLs(certTocheck, CRLS, trustedCerts)
    protected void checkCRL(X509Certificate cert, 
                CertificateRevocationLists crlsList, 
                TrustedCertificates trustedCerts) 
    throws ProxyPathValidatorException {
    if (crlsList == null) {
        return;
    }

    logger.debug("checkCRLs: enter");
    // Should not happen, just a sanity check.
    if (trustedCerts == null) {
        String err = i18n.getMessage("proxyErr19");
        logger.error(err);
        throw new ProxyPathValidatorException(
            ProxyPathValidatorException.FAILURE, null, err);
    }

    String issuerName = cert.getIssuerDN().getName();
    X509CRL crl = crlsList.getCrl(issuerName);
    if (crl == null) {
        logger.debug("No CRL for certificate");
        return;
    }

    // get CA cert for the CRL
    X509Certificate x509Cert = 
        trustedCerts.getCertificate(issuerName);
    if (x509Cert == null) {
        // if there is no trusted certs from that CA, then
        // the chain cannot contain a cert from that CA,
        // which implies not checking this CRL should be fine.
        logger.debug("No trusted cert with this CA signature");
        return;
    }
    
    // validate CRL
    try {
        crl.verify(x509Cert.getPublicKey());
    } catch (Exception exp) {
            String err = i18n.getMessage("proxyErr20");
            logger.error(err);
        throw new ProxyPathValidatorException(
                ProxyPathValidatorException.FAILURE, err, exp);
    }

    //check date validity of CRL
        boolean validCRL = checkCRLValidity(crl);
        if (validCRL) {
        if (crl.isRevoked(cert)) {
        throw new 
                    ProxyPathValidatorException(ProxyPathValidatorException
                                                .REVOKED, cert,
                                                i18n.getMessage("proxyErr21",
                                                                cert.getSubjectDN().getName()));
            }
    } else {
            throw new 
                ProxyPathValidatorException(ProxyPathValidatorException
                                            .EXPIRED_CRL, cert,
                                            i18n.getMessage("proxyErr36",
                                                            issuerName));
        }
        
    logger.debug("checkCRLs: exit");
    }

    protected boolean checkCRLValidity(X509CRL crl) {

    Date now = new Date();     
        return (crl.getThisUpdate().before(now) &&
                ((crl.getNextUpdate()!=null) && 
                 (crl.getNextUpdate().after(now))));
            
    }

    protected void checkSigningPolicy(X509Certificate certificate,
                                      TrustedCertificates trustedCerts,
                                      Boolean enforceSigningPolicy) 
        throws ProxyPathValidatorException {

        boolean enforcePolicy = true;
        if (enforceSigningPolicy != null) {
            enforcePolicy = enforceSigningPolicy.booleanValue();
        } else {
             enforcePolicy = CoGProperties.getDefault().enforceSigningPolicy();
         }

        if (!enforcePolicy) {
            return;
        }

         String issuerName = certificate.getIssuerDN().getName();
         String issuerGlobusId = CertificateUtil.toGlobusID(issuerName, true);
         SigningPolicy policy = trustedCerts.getSigningPolicy(issuerGlobusId);
         if (policy == null) {
             String err = i18n.getMessage("proxyErr33", issuerGlobusId);
             throw new 
                 ProxyPathValidatorException(ProxyPathValidatorException
                                             .NO_SIGNING_POLICY_FILE, err,
                                             null);
         } 

         String certDN = certificate.getSubjectDN().toString();
         String certDNGlobus = CertificateUtil.toGlobusID(certDN, true);
         if (policy.isPolicyAvailable()) {
             boolean isValidDN = policy.isValidSubject(CertificateUtil.toPrincipal(certDNGlobus));
             if (!isValidDN) {
                 String err = 
                     i18n.getMessage("proxyErr34", 
                                     new Object[] { certDNGlobus, 
                                                    issuerGlobusId,
                                                    policy.getCASubjectDN().getName() });
                 throw new 
                     ProxyPathValidatorException(ProxyPathValidatorException
                                                 .SIGNING_POLICY_VIOLATION, err,
                                                 null);
             }
         } else {
             String err = 
                 i18n.getMessage("proxyErr35", 
                                 new Object[] { issuerGlobusId,
                     policy.getCASubjectDN().getName() });
             throw new 
                 ProxyPathValidatorException(ProxyPathValidatorException
                                             .NO_SIGNING_POLICY, err,
                                             null);
         }
    }
    
    // if a certificate is not a CA or if it is not a proxy, return true.
    private boolean requireSigningPolicyCheck(int certType) {

        if (ProxyCertificateUtil.isProxy(certType) || (certType == GSIConstants.CA)) {
            return false;
        }
        return true;
    }

}
