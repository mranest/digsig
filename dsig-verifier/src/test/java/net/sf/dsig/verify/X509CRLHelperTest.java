package net.sf.dsig.verify;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import junit.framework.TestCase;

import org.apache.xml.security.utils.Base64;

public class X509CRLHelperTest extends TestCase {

	private final String TEST_CERTIFICATE = 
		"MIIFDjCCBHegAwIBAgIQMhkZ35XvUvCIFaOllXrVrDANBgkqhkiG9w0BAQUFADCBnDELMAkGA1UE" +
		"BhMCR1IxIzAhBgNVBAoTGkVGRyBFdXJvYmFuayBFcmdhc2lhcyBBLkUuMR8wHQYDVQQLExZWZXJp" +
		"U2lnbiBUcnVzdCBOZXR3b3JrMR8wHQYDVQQLExZGT1IgVEVTVCBQVVJQT1NFUyBPTkxZMSYwJAYD" +
		"VQQDEx1FRkcgRXVyb2JhbmsgRXJnYXNpYXMgVEVTVCBDQTAeFw0wOTA0MTEwMDAwMDBaFw0xMDA0" +
		"MTEyMzU5NTlaMIHwMRUwEwYDVQQLFAxBbGlhcyAtIGRzaWcxCzAJBgNVBAYTAkdSMR8wHQYDVQQL" +
		"FBZGT1IgVEVTVCBQVVJQT1NFUyBPTkxZMTEwLwYDVQQLFChUZXJtcyBvZiB1c2UgYXQgc2VjLmFk" +
		"YWNvbS5jb20vcnBhIChjKTAzMSMwIQYDVQQKFBpFRkcgRXVyb2JhbmsgRXJnYXNpYXMgQS5FLjEP" +
		"MA0GA1UEDBQGU2FtcGxlMRIwEAYDVQQEEwlTaWduYXR1cmUxEDAOBgNVBCoTB0RpZ2l0YWwxGjAY" +
		"BgNVBAMTEURpZ2l0YWwgU2lnbmF0dXJlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA" +
		"ppx3we7zNqNzUNqmi9IiREM+/gEnps7ExiGMijeibVbiQcx93oT7vxuvFlGeWnu9KIdpO0Dbalak" +
		"Nx+Lg8HaqEmtwUvHuHJ56VWdh5+IvQKp7Z8b6608rlyaZ9s3/PnYp3bG+uFngQ1sAQp9I0a7m0J9" +
		"Kv4SR75svPKxNspGQeDdj0oXLEFEmX7k82bDiTd6hrPp2bwpn9qnSxWXih5dFmy6DBut3eiOIlSE" +
		"LrKQhPI2zMwHrX6R0lpwlWuUhZDmzNpmF5p8u2YetCR5zvP0rhuZ6QIOAM87z/uigacT+6T8pxfK" +
		"BbdAT3fJWi/MhLuxWQqN9TU5NpTNtrjWr4mthwIDAQABo4IBdTCCAXEwCQYDVR0TBAIwADALBgNV" +
		"HQ8EBAMCBeAwWwYDVR0gBFQwUjA3BgtghkgBhvhFAQcXAjAoMCYGCCsGAQUFBwIBFhpodHRwczov" +
		"L3NlYy5hZGFjb20uY29tL3JwYTANBgtghkgBhvhFAQcsAjAIBgYEAIswAQEwYgYDVR0fBFswWTBX" +
		"oFWgU4ZRaHR0cDovL2NybC10ZXN0LmFkYWNvbS5jb20vRUZHRXVyb2JhbmtFcmdhc2lhc0FFRk9S" +
		"VEVTVFBVUlBPU0VTT05MWS9MYXRlc3RDUkwuY3JsMBEGCWCGSAGG+EIBAQQEAwIHgDARBgpghkgB" +
		"hvhFAQYJBAMBAf8wHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMBgGCCsGAQUFBwEDBAww" +
		"CjAIBgYEAI5GAQEwNwYIKwYBBQUHAQEEKzApMCcGCCsGAQUFBzABhhtodHRwOi8vb2NzcC10ZXN0" +
		"LmFkYWNvbS5jb20wDQYJKoZIhvcNAQEFBQADgYEAkflhsm/1ljYzAIhJn1uYFOER1ZHIchON/sjh" +
		"V/UeATrycM2GJSj+/o6LlcQlmHSpwOPVCF5onTKDpNM++lvURQLbSgOTHw6kB9uVeW4oBI8ALk9H" +
		"m23BK53XkvhwtnQ/L1pHalcWoGp2dFk+PzKZzmmniWQ00gemA4xNO5HDNWA=";
	
	public static X509CRLHelper getCrlHelper() {
		X509CRLHelper helper = new X509CRLHelper();
		helper.setProxyHost(System.getProperty("http.proxyHost"));
		helper.setProxyPort(
				Integer.getInteger("http.proxyPort") != null ? 
				Integer.getInteger("http.proxyPort").intValue() : -1);
		

		return helper;
	}
	
	public void testHelper() throws Exception {
		X509Certificate certificate = (X509Certificate) 
				CertificateFactory.getInstance("X.509").generateCertificate(
							new ByteArrayInputStream(Base64.decode(TEST_CERTIFICATE)));
		
		assertNotNull(certificate);
		
		String distributionPointUriAsString = 
			X509CRLHelper.getCRLDistributionPointUri(certificate);
		
		assertNotNull(distributionPointUriAsString);
		assertEquals(
				"http://crl-test.adacom.com/EFGEurobankErgasiasAEFORTESTPURPOSESONLY/LatestCRL.crl", 
				distributionPointUriAsString);
		
		X509CRLHelper helper = getCrlHelper();
		
		assertNotNull(helper.getX509CRL(distributionPointUriAsString));
		
		assertFalse(helper.uriNextUpdateMap.isEmpty());
		assertFalse(helper.uriX509CrlMap.isEmpty());
		
		assertTrue(helper.isValid(certificate));
	}
	
}
