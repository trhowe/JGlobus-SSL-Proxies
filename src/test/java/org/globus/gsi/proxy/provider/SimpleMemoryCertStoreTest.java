package org.globus.gsi.proxy.provider;

import java.security.cert.X509CRLSelector;
import java.security.cert.X509CertSelector;
import org.junit.AfterClass;
import org.springframework.core.io.ClassPathResource;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.security.Security;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

public class SimpleMemoryCertStoreTest {

   private static X509Certificate cert;
   private static X509CRL crl;
   private SimpleMemoryCertStore store;
    
    @BeforeClass
    public static void loadBouncyCastleProvider() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        CertificateFactory factory = CertificateFactory.getInstance("X.509", "BC");
        cert = (X509Certificate) factory.generateCertificate(
            new ClassPathResource("org/globus/gsi/proxy/test/usercert.pem").getInputStream());
        crl = (X509CRL) factory.generateCRL(
            new ClassPathResource("org/globus/gsi/proxy/test/ca2crl.r0").getInputStream());
    }

    @Test
    public void testEngineGetCRLsCRLSelector() throws Exception {
        SimpleMemoryCertStoreParams params = new SimpleMemoryCertStoreParams(null, null);
        store = new SimpleMemoryCertStore(params);
        assertEquals(0, store.engineGetCRLs(new X509CRLSelector()).size());

        params = new SimpleMemoryCertStoreParams(new X509Certificate[] {cert}, new X509CRL[] {crl});
        store = new SimpleMemoryCertStore(params);
        assertEquals(1, store.engineGetCRLs(new X509CRLSelector()).size());

        X509CRLSelector crlSelector = new X509CRLSelector();
        crlSelector.addIssuerName("CN=non-existent");
        assertEquals(0, store.engineGetCRLs(crlSelector).size());
    }

    @Test
    public void testEngineGetCertificatesCertSelector() throws Exception {
        SimpleMemoryCertStoreParams params = new SimpleMemoryCertStoreParams(null, null);
        store = new SimpleMemoryCertStore(params);
        assertEquals(0, store.engineGetCertificates(new X509CertSelector()).size());

        params = new SimpleMemoryCertStoreParams(new X509Certificate[] {cert}, new X509CRL[] {crl});
        store = new SimpleMemoryCertStore(params);
        assertEquals(1, store.engineGetCertificates(new X509CertSelector()).size());

        params = new SimpleMemoryCertStoreParams(new X509Certificate[] {cert}, new X509CRL[] {crl});
        store = new SimpleMemoryCertStore(params);
        X509CertSelector selector = new X509CertSelector();
        // with BC as provider for the factory, this fails if i do getSubjectDN().toString()
        selector.setSubject(cert.getSubjectX500Principal());
        assertEquals(1, store.engineGetCertificates(selector).size());

        X509CertSelector certSelector = new X509CertSelector();
        certSelector.setSubject("CN=non-existent");
        assertEquals(0, store.engineGetCertificates(certSelector).size());
        
    }

}
