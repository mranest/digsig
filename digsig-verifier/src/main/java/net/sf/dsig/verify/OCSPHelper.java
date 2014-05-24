/*
 * Copyright 2007-2014 Anestis Georgiadis
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

package net.sf.dsig.verify;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Vector;

import org.apache.commons.httpclient.HostConfiguration;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.commons.httpclient.methods.ByteArrayRequestEntity;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.CertificateStatus;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.SingleResp;

/**
 * A helper class that encapsulates OCSP checking logic
 * 
 * @author <a href="mailto:mranest@iname.com">Anestis Georgiadis</a>
 * @see <a href="http://forums.sun.com/thread.jspa?threadID=5133153">OCSP Client</a>
 */
public class OCSPHelper {

    private static final String OID_AUTHORITYINFOACCESS = "1.3.6.1.5.5.7.1.1";
    
    private static final Log logger = LogFactory.getLog(OCSPHelper.class);
    
    static {
        if (Security.getProperty("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
    
    private X509Certificate caCertificate;
    
    public void setCaCertificate(X509Certificate caCertificate) {
        this.caCertificate = caCertificate;
    }
    
    private String proxyHost;
    
    public void setProxyHost(String proxyHost) {
        this.proxyHost = proxyHost;
    }
    
    private int proxyPort = -1;
    
    public void setProxyPort(int proxyPort) {
        this.proxyPort = proxyPort;
    }
    
    private String defaultOcspAccessLocation = null;
    
    public void setDefaultOcspAccessLocation(String defaultOcspAccessLocation) {
        this.defaultOcspAccessLocation = defaultOcspAccessLocation;
    }
    
    private HostConfiguration getHostConfiguration() {
        HostConfiguration config = new HostConfiguration();
        
        if (proxyHost != null && proxyPort != -1) {
            logger.debug("Setting proxy" + 
                    "; proxyHost=" + proxyHost +
                    "; proxyPort=" + proxyPort);
            config.setProxy(proxyHost, proxyPort);
        }
        
        return config;
    }

    private HttpClient client = new HttpClient(new MultiThreadedHttpConnectionManager());
    
    /**
     * Check with OCSP protocol whether a certificate is valid
     * 
     * @param certificate an {@link X509Certificate} object
     * @return true if the certificate is valid; false otherwise
     * @throws NetworkAccessException when any network access issues occur
     * @throws VerificationException when an OCSP related error occurs
     */
    public boolean isValid(X509Certificate certificate) 
    throws NetworkAccessException, VerificationException {
        PostMethod post = null;
        
        try {
            CertificateID cid = new CertificateID(
                    CertificateID.HASH_SHA1,
                    caCertificate,
                    certificate.getSerialNumber());
            
            OCSPReqGenerator gen = new OCSPReqGenerator();
            gen.addRequest(cid);

            // Nonce
            BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
            Vector oids = new Vector();
            Vector values = new Vector();
            oids.add(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            values.add(new X509Extension(false, new DEROctetString(nonce.toByteArray())));
            values.add(new X509Extension(false, new DEROctetString(
                    new BigInteger("041063FAB2B54CF1ED014F9DF7C70AACE575", 16).toByteArray())));
            gen.setRequestExtensions(new X509Extensions(oids, values));
            
            // Requestor name - not really required, but added for completeness
//          gen.setRequestorName(
//                  new GeneralName(
//                          new X509Name(
//                                  certificate.getSubjectX500Principal().getName())));
            
            logger.debug("Generating OCSP request" +
                    "; serialNumber=" + certificate.getSerialNumber().toString(16) +
                    ", nonce=" + nonce.toString(16) +
                    ", caCertificate.subjectName=" + caCertificate.getSubjectX500Principal().getName()); 
            
            // TODO Need to call the generate(...) method, that signs the 
            // request. Which means, need to have a keypair for that, too
            OCSPReq req = gen.generate();
            
            // First try finding the OCSP access location in the X.509 certificate
            String uriAsString = getOCSPAccessLocationUri(certificate);
            
            // If not found, try falling back to the default
            if (uriAsString == null) {
                uriAsString = defaultOcspAccessLocation; 
            }
            
            // If still null, bail out
            if (uriAsString == null) {
                throw new ConfigurationException("OCSP AccessLocation not found on certificate, and no default set");
            }
            
            HostConfiguration config = getHostConfiguration();
            
            post = new PostMethod(uriAsString);
            post.setRequestHeader("Content-Type", "application/ocsp-request");
            post.setRequestHeader("Accept", "application/ocsp-response");
            post.setRequestEntity(new ByteArrayRequestEntity(req.getEncoded()));
        
            client.executeMethod(config, post);
            
            logger.debug("HTTP POST executed" + 
                    "; authorityInfoAccessUri=" + uriAsString +
                    ", statusLine=" + post.getStatusLine());
                    
            if (post.getStatusCode() != HttpStatus.SC_OK) {
                throw new NetworkAccessException("HTTP GET failed; statusLine=" + post.getStatusLine());
            }
            
            byte[] responseBodyBytes = post.getResponseBody();
            
            OCSPResp ocspRes = new OCSPResp(responseBodyBytes);
            if (ocspRes.getStatus() != OCSPResponseStatus.SUCCESSFUL) {
                // One possible exception is the use of a wrong CA certificate
                throw new ConfigurationException(
                        "OCSP request failed; possibly wrong issuer/user certificate" +
                        "; status=" + ocspRes.getStatus());
            }
            
            BasicOCSPResp res = (BasicOCSPResp) ocspRes.getResponseObject();
            SingleResp[] responses = res.getResponses();
            SingleResp response = responses[0];
            
            CertificateStatus status = (CertificateStatus) response.getCertStatus();
            // Normal OCSP protocol allows a null status
            return status == null || status == CertificateStatus.GOOD;
        } catch (IOException e) {
            throw new NetworkAccessException("I/O error occured", e);
        } catch (OCSPException e) {
            throw new VerificationException("Error while following OCSP protocol", e);
        } finally {
            if (post != null) {
                post.releaseConnection();
            }
        }
    }
    
    /**
     * Retrieve the OCSP URI distribution point from an X.509 certificate, using
     * the 1.3.6.1.5.5.7.1.1 extension value
     * 
     * @param certificate the {@link X509Certificate} object
     * @return a String containing the URI of the OCSP authority info access,
     * or null if none can be found
     */
    public static String getOCSPAccessLocationUri(X509Certificate certificate) {
        try {
            byte[] derAiaBytes = certificate.getExtensionValue(OID_AUTHORITYINFOACCESS);
            if (derAiaBytes == null) {
                return null;
            }
            
            ASN1InputStream ais = new ASN1InputStream(derAiaBytes);
            DEROctetString dos = (DEROctetString) ais.readObject();
            ais.close();
            
            ais = new ASN1InputStream(dos.getOctets());
            DERSequence seq = (DERSequence) ais.readObject();
            ais.close();
            
            AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(seq);
            
            for (int i=0; i<aia.getAccessDescriptions().length; i++) {
                AccessDescription ad = aia.getAccessDescriptions()[i];
                if (!ad.getAccessMethod().equals(AccessDescription.id_ad_ocsp)) {
                    continue;
                }
                
                GeneralName gn = ad.getAccessLocation();
                if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                    return ((DERString) gn.getName()).getString();
                }
            }
        } catch (IOException e) {
            logger.warn("ASN.1 decoding failed; will fall back to default OCSP AccessLocation, if set");
        }
        
        return null;
    }
    
}
