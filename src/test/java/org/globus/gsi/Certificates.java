package org.globus.gsi;

import org.globus.security.util.CertificateLoadUtil;

import java.io.InputStream;

import java.security.cert.X509Certificate;

public class Certificates {

    public static final String BASE = "org/globus/gsi/proxy/test/";
    public static X509Certificate[] goodCertsArr;

    public static String[][] certs = {
            { String.valueOf(GSIConstants.CA), "globusca.pem" },
            { String.valueOf(GSIConstants.EEC), "usercert.pem" },
            { String.valueOf(GSIConstants.GSI_2_PROXY), "gsi2fullproxy.pem" },
            { String.valueOf(GSIConstants.GSI_2_LIMITED_PROXY), "gsi2limitedproxy.pem" },
            // double
            { String.valueOf(GSIConstants.GSI_2_LIMITED_PROXY), "gsi2limited2xproxy.pem" },
            { String.valueOf(GSIConstants.GSI_3_IMPERSONATION_PROXY), "gsi3impersonationproxy.pem" },
            { String.valueOf(GSIConstants.GSI_3_INDEPENDENT_PROXY), "gsi3independentproxy.pem" },
            { String.valueOf(GSIConstants.GSI_3_LIMITED_PROXY), "gsi3limitedproxy.pem" },
            { String.valueOf(GSIConstants.GSI_3_RESTRICTED_PROXY), "gsi3restrictedproxy.pem" },
            // double
            { String.valueOf(GSIConstants.GSI_3_IMPERSONATION_PROXY), "gsi3impersonation2xproxy.pem" },
            { String.valueOf(GSIConstants.GSI_3_INDEPENDENT_PROXY), "gsi3independent2xproxy.pem" },
            // pathLen = 0
            { String.valueOf(GSIConstants.GSI_3_IMPERSONATION_PROXY), "gsi3impersonationp0proxy.pem" },
            // pathLen = 1
            { String.valueOf(GSIConstants.GSI_3_INDEPENDENT_PROXY), "gsi3independentp1proxy.pem" },
            // pathLen = 2
            { String.valueOf(GSIConstants.CA), "testca.pem" },
            { String.valueOf(GSIConstants.EEC), "testeec1.pem" },
            { String.valueOf(GSIConstants.EEC), "testeec2.pem" },
            // pathLen = 1
            { String.valueOf(GSIConstants.CA), "testca2.pem" },
            { String.valueOf(GSIConstants.GSI_3_IMPERSONATION_PROXY), "testgsi3proxy.pem" },
            // for CRL test
            { String.valueOf(GSIConstants.CA), "testca3.pem" },
            { String.valueOf(GSIConstants.EEC), "crl_usercert.pem" },
            { String.valueOf(GSIConstants.GSI_2_PROXY), "crl_proxy.pem" },
            // 21 (all good)
            { String.valueOf(GSIConstants.CA), "ca1cert.pem" }, { String.valueOf(GSIConstants.EEC), "user1ca1.pem" },
            { String.valueOf(GSIConstants.EEC), "user2ca1.pem" }, { String.valueOf(GSIConstants.EEC), "user3ca1.pem" },
            // 25
            { String.valueOf(GSIConstants.CA), "ca2cert.pem" },
            // must be revoked (in ca2crl.r0)
            { String.valueOf(GSIConstants.EEC), "user1ca2.pem" },
            // must be revoked (in ca2crl.r0)
            { String.valueOf(GSIConstants.EEC), "user2ca2.pem" }, { String.valueOf(GSIConstants.EEC), "user3ca2.pem" } };

    public static String[] badCerts = {
        "-----BEGIN CERTIFICATE-----\n"
            + "MIICFTCCAX6gAwIBAgIDClb3MA0GCSqGSIb3DQEBBAUAMGIxCzAJBgNVBAYTAlVT\n"
            + "MQ8wDQYDVQQKEwZHbG9idXMxJDAiBgNVBAoTG0FyZ29ubmUgTmF0aW9uYWwgTGFi\n"
            + "b3JhdG9yeTEMMAoGA1UECxMDTUNTMQ4wDAYDVQQDEwVnYXdvcjAeFw0wMjEyMTgw\n"
            + "NzEzNDhaFw0wMjEyMTgxOTE4NDhaMIGCMQswCQYDVQQGEwJVUzEPMA0GA1UEChMG\n"
            + "R2xvYnVzMSQwIgYDVQQKExtBcmdvbm5lIE5hdGlvbmFsIExhYm9yYXRvcnkxDDAK\n"
            + "BgNVBAsTA01DUzEOMAwGA1UEAxMFZ2F3b3IxDjAMBgNVBAMTBXByb3h5MQ4wDAYD\n"
            + "VQQDEwVwcm94eTBaMA0GCSqGSIb3DQEBAQUAA0kAMEYCQQCplfu3OZH5AfYgoYKi\n"
            + "KFmGZnbj3+ZwJm45B6Ef7qwW7Le7FP4eirljObqijgn8ao0gGqy38LYbaTntToqX\n"
            + "iy5fAgERMA0GCSqGSIb3DQEBBAUAA4GBAKnNy0VPDzzD6++7i9a/yegPX2+OVI6C\n"
            + "7oss1/4sSw2gfn/q8qNiGdt1kr4W3JJACdjgnik8fokNS7pDMdXKi3Wx6E0HhgKz\n"
            + "eRIm5r6Vj7nshVBAv60Xmfju3yaOZsDnj8p0t8Fjc8ekeZowLEdRn7PCEQPylMOp\n"
            + "2puR03MaPiFj\n"
            + "-----END CERTIFICATE-----",
        "-----BEGIN CERTIFICATE-----\n" 
            + "MIICBDCCAW2gAwIBAgIDAx4rMA0GCSqGSIb3DQEBBAUAMGIxCzAJBgNVBAYTAlVT\n"
            + "MQ8wDQYDVQQKEwZHbG9idXMxJDAiBgNVBAoTG0FyZ29ubmUgTmF0aW9uYWwgTGFi\n"
            + "b3JhdG9yeTEMMAoGA1UECxMDTUNTMQ4wDAYDVQQDEwVnYXZvcjAeFw0wMjEyMTgw\n"
            + "NzIxMThaFw0wMjEyMTgxOTI2MThaMHIxCzAJBgNVBAYTAlVTMQ8wDQYDVQQKEwZH\n"
            + "bG9idXMxJDAiBgNVBAoTG0FyZ29ubmUgTmF0aW9uYWwgTGFib3JhdG9yeTEMMAoG\n"
            + "A1UECxMDTUNTMQ4wDAYDVQQDEwVnYXdvcjEOMAwGA1UEAxMFcHJveHkwWjANBgkq\n"
            + "hkiG9w0BAQEFAANJADBGAkEAx2fp80b+Yo0zCwjYJdIjzn0N3ezzcD2h2bAr/Nop\n"
            + "w/H6JB4heiVGMeydMlSJHyI7J/s5l8k39G/KVrBGT9tRJwIBETANBgkqhkiG9w0B\n"
            + "AQQFAAOBgQCRRvTdW6Ddn1curWm515l/GoAoJ76XBFJWfusIZ9TdwE8hlkRpK9Bd\n"
            + "Rrao4Z2YO+e3UItn45Hs+8gzx+jBB1AduTUor603Z8AXaNbF/c+gz62lBWlcmZ2Y\n"
            + "LzuUWgwZLd9HdA2YBgCcT3B9VFmBxcnPjGOwWT29ZUtyy2GXFtzcDw==\n" 
            + "-----END CERTIFICATE-----" };

    public static String[] testCerts = {
        "-----BEGIN CERTIFICATE-----\n"
            + "MIIB7zCCAVigAwIBAgICAbowDQYJKoZIhvcNAQEEBQAwVzEbMBkGA1UEChMSZG9l\n"
            + "c2NpZW5jZWdyaWQub3JnMQ8wDQYDVQQLEwZQZW9wbGUxJzAlBgNVBAMTHlZpamF5\n"
            + "YSBMYWtzaG1pIE5hdGFyYWphbiAxNzkwODAeFw0wMzAxMTcyMjExMjJaFw0wMzAx\n"
            + "MTgxMDE2MjJaMGcxGzAZBgNVBAoTEmRvZXNjaWVuY2VncmlkLm9yZzEPMA0GA1UE\n"
            + "CxMGUGVvcGxlMScwJQYDVQQDEx5WaWpheWEgTGFrc2htaSBOYXRhcmFqYW4gMTc5\n"
            + "MDgxDjAMBgNVBAMTBXByb3h5MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANGP+xct\n"
            + "lDYMPm11QKnACvqs95fbPRehvUi6/dizZ+VrDOU1OTUoXA0t6HRgtmJ8XthEUKxU\n"
            + "MVsxjXtoZOzfuFECAwEAATANBgkqhkiG9w0BAQQFAAOBgQBqFTcN/qqvTnyI4z26\n"
            + "lv1lMTuRIjL9l6Ug/Kwxuzjpl088INky1myFPjKsWMYzh9nXIQg9gg2dJTno5JHB\n"
            + "++u0Fw2iNrTjswu4hvqYZn+LoSGchH2XyCUssuOWCbW4IkN8/Xzfre2oC2EieECC\n"
            + "w+jjGhcqPrxvkHh8xXYroqA0Sg==\n" 
            + "-----END CERTIFICATE-----",
        "-----BEGIN CERTIFICATE-----\n"
            + "MIIDLDCCAhSgAwIBAgICAbowDQYJKoZIhvcNAQEFBQAwdTETMBEGCgmSJomT8ixk\n"
            + "ARkWA25ldDESMBAGCgmSJomT8ixkARkWAmVzMSAwHgYDVQQLExdDZXJ0aWZpY2F0\n"
            + "ZSBBdXRob3JpdGllczEZMBcGA1UECxMQRE9FIFNjaWVuY2UgR3JpZDENMAsGA1UE\n"
            + "AxMEcGtpMTAeFw0wMjA5MjMyMzQ2NDRaFw0wMzA5MjMyMzQ2NDRaMFcxGzAZBgNV\n"
            + "BAoTEmRvZXNjaWVuY2VncmlkLm9yZzEPMA0GA1UECxMGUGVvcGxlMScwJQYDVQQD\n"
            + "Ex5WaWpheWEgTGFrc2htaSBOYXRhcmFqYW4gMTc5MDgwgZ8wDQYJKoZIhvcNAQEB\n"
            + "BQADgY0AMIGJAoGBAORYHsPQU3yVlTsC/29CDoEYF82PVlolQk5s+1m6A7m3VvML\n"
            + "TKh4ja6cKtq7C5rBUIWdyklkU3eXSSmiAzjJrVOmfWK3RR465A5tfvJLmXKWaq3U\n"
            + "7SvI6v3vx4Jzy4MJs46TDAr4v9JRJG2yshoxruRy2gDsn4F5NfLLevDNwzSLAgMB\n"
            + "AAGjaDBmMBEGCWCGSAGG+EIBAQQEAwIF4DAOBgNVHQ8BAf8EBAMCBPAwHwYDVR0j\n"
            + "BBgwFoAUVBeIygPBOSa4VabEmfQrAqu+AOkwIAYDVR0RBBkwF4EVdmlqYXlhbG5A\n"
            + "bWF0aC5sYmwuZ292MA0GCSqGSIb3DQEBBQUAA4IBAQC/dxf5ZuSrNrxslHUZfDle\n"
            + "V8SPnX5roBUOuO2EPpEGYHB25Ca+TEi0ra0RSRuZfGmY13/aS6CzjBF+6GED9MLo\n"
            + "6UdP1dg994wpGZ2Mj0dZoGE7we10NrSvFAS3u7uXrTTegeJoDpo1k9YVsOkK9Lu9\n"
            + "Sg+EztnMGa1BANWf779Qws5J9xUR2Nip0tBkV3IRORcBx0CoZzQnDIWyppmnkza2\n"
            + "mhgEv6CXYYB4ucCFst0P2Q3omcWrtHexoueMGOV6PtLFBst5ReOaZWU+q2D30t3b\n"
            + "GFITa0aayXTlb6gWgo3z/O/K5GZS5jF+BA3j1e8IhxqeibT1rVHF4W4ZMjGhBcwa\n" 
            + "-----END CERTIFICATE-----",
        "-----BEGIN CERTIFICATE-----\n" 
            + "MIIEqjCCBBOgAwIBAgIBLzANBgkqhkiG9w0BAQUFADBbMRkwFwYDVQQKExBET0Ug\n"
            + "U2NpZW5jZSBHcmlkMSAwHgYDVQQLExdDZXJ0aWZpY2F0ZSBBdXRob3JpdGllczEc\n"
            + "MBoGA1UEAxMTQ2VydGlmaWNhdGUgTWFuYWdlcjAeFw0wMTEyMjEyMzQ4MzdaFw0w\n"
            + "NDAxMTAyMzQ4MzdaMHUxEzARBgoJkiaJk/IsZAEZFgNuZXQxEjAQBgoJkiaJk/Is\n"
            + "ZAEZFgJlczEgMB4GA1UECxMXQ2VydGlmaWNhdGUgQXV0aG9yaXRpZXMxGTAXBgNV\n"
            + "BAsTEERPRSBTY2llbmNlIEdyaWQxDTALBgNVBAMTBHBraTEwggEiMA0GCSqGSIb3\n"
            + "DQEBAQUAA4IBDwAwggEKAoIBAQDhgzoAt5viFffXWG6P0KSf/dO0mrEbgpuKIHDa\n"
            + "RdHkxJGaoBgRO2D+YV4Wh+JcKlz64v2ScYHCgGbKoaE+cGM/O06xkLCV0pyT4Xvj\n"
            + "6/R80jqwzzRw8aYz9iE/wjljK1ehb+oJ6TJlnotCVBd7TlHODYfXXblt67/Uk1uu\n"
            + "4l17jCdfk4mUn/2Bdeae4EMibj7Vc1dkPkyY47ZADTeFXMNDyp4yGFeIDZQ6h+YH\n"
            + "27+t1/TDuEH1R4PpklRpSbppGprI8hv2P6uEKTySjAEkww9xVzenN6oULeafFJuS\n"
            + "t6Ui6BFxc1OuxMq/s0PDiFh8bPMhzJWBfzaNPHnYrFDWcDwHAgMBAAGjggHeMIIB\n"
            + "2jAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0OBBYEFFQXiMoDwTkmuFWmxJn0KwKrvgDp\n"
            + "MB8GA1UdIwQYMBaAFJvOT/K8vVhwMdXyMg5+nr3iURTnMA8GA1UdEwEB/wQFMAMB\n"
            + "Af8wgY8GA1UdHwSBhzCBhDCBgaAaoBiGFmh0dHA6Ly9lbnZpc2FnZS5lcy5uZXSB\n"
            + "AgDsol+kXTBbMRkwFwYDVQQKExBET0UgU2NpZW5jZSBHcmlkMSAwHgYDVQQLExdD\n"
            + "ZXJ0aWZpY2F0ZSBBdXRob3JpdGllczEcMBoGA1UEAxMTQ2VydGlmaWNhdGUgTWFu\n"
            + "YWdlcjCB5AYDVR0gBIHcMIHZMIHWBgoqhkiG90wDBgQBMIHHMF8GCCsGAQUFBwIC\n"
            + "MFMwJhYfRVNuZXQgKEVuZXJneSBTY2llbmNlcyBOZXR3b3JrKTADAgEBGilFU25l\n"
            + "dC1ET0UgU2NpZW5jZSBHcmlkIENlcnRpZmljYXRlIFBvbGljeTBkBggrBgEFBQcC\n"
            + "ARZYaHR0cDovL2VudmlzYWdlLmVzLm5ldC9FbnZpc2FnZSUyMERvY3MvRE9FU0cl\n"
            + "MjBDQSUyMENlcnRpZmljYXRlJTIwUG9saWN5JTIwYW5kJTIwQ1BTLnBkZjANBgkq\n"
            + "hkiG9w0BAQUFAAOBgQCaAdUregqwmCJG6j/h6uK2bTpcfa/SfpaYwsTy+zlf5r4P\n"
            + "iY/wIRN0ZjJ4RrJQ/WUH16onNwb87JnYe0V4JYhATAOnp/5y9kl+iC4XvHBioVxm\n"
            + "3sEADL40WAVREWBGZnyFqysXAEGfk+Wg7um5FzCwi6380GASKY0VujQG03f6Pg==\n" 
            + "-----END CERTIFICATE-----" };

    // Globus CA signing policy. Using globusca.pem and usercert.pem
    public static String signingPolicy = "# Globus CA rights\naccess_id_CA      X509         '/C=US/O=Globus/CN=Globus Certification Authority'\npos_rights        globus        CA:sign\ncond_subjects     globus       '\"/C=us/O=Globus/*\"  \"/C=US/O=Globus/*\"'\n# End of ca-signing-policy.conf";

    // Globus CA signing policy that causes usercert.pem to violate
    // the policy
    public static String signingPolicyViolation = "# Globus CA rights\naccess_id_CA      X509         '/C=US/O=Globus/CN=Globus Certification Authority'\npos_rights        globus        CA:sign\ncond_subjects     globus       '\"/C=usa/O=Globus/*\"  \"/C=USA/O=Globus/*\"'\n# End of ca-signing-policy.conf";

    // Globus CA signing policy without relevant signing policy
    public static String signingPolicySansPolicy = "# Globus CA rights\naccess_id_CA      nonX509         '/C=US/O=Globus/CN=Globus Certification Authority'\npos_rights        globus        CA:sign\ncond_subjects     globus       '\"/C=usa/O=Globus/*\"  \"/C=USA/O=Globus/*\"'\n# End of ca-signing-policy.conf";

    public static X509Certificate[] initCerts() throws Exception {
        X509Certificate[] goodCertsArr = new X509Certificate[certs.length];
        ClassLoader loader = Certificates.class.getClassLoader();
        for (int i = 0; i < certs.length; i++) {
            String name = BASE + certs[i][1];
            InputStream in = loader.getResourceAsStream(name);
            if (in == null) {
                throw new Exception("Unable to load: " + name);
            }
            goodCertsArr[i] = CertificateLoadUtil.loadCertificate(in);
        }
        return goodCertsArr;
    }

    public static X509Certificate getCertificate(int i) throws Exception {
        ClassLoader loader = Certificates.class.getClassLoader();
        String name = BASE + certs[i][1];
        InputStream in = loader.getResourceAsStream(name);
        if (in == null) {
            throw new Exception("Unable to load: " + name);
        }
        return CertificateLoadUtil.loadCertificate(in);
    }

    static {
        try {
            goodCertsArr = initCerts();
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Failed to load certs: " + e);
        }
    }

}
