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
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Set;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.signature.ObjectContainer;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

/**
 * Verify all aspects of an XML Digital Signature. Core verification is done
 * through use of Apache XML Security library. Certificate chain validation 
 * is done through use of JRE's PKIX algorithm. CRL and OCSP checks are performed
 * by delegating to the corresponding helpers, if injected.
 * 
 * @author <a href="mailto:mranest@iname.com">Anestis Georgiadis</a>
 */
public class XmldsigVerifier {

    private static final Log logger = LogFactory.getLog(XmldsigVerifier.class);
    
    static {
        org.apache.xml.security.Init.init();
    }
    
    private DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();

    {
        builderFactory.setNamespaceAware(true);
    }

    /**
     * <p>A regular expression that is tested against the subject of the
     * certificate. When set only matching certificates are accepted
     * and displayed for selection.
     */
    private String subjectMatchingRegex = null;
    
    public void setSubjectMatchingRegex(String subjectRegex) {
        this.subjectMatchingRegex = subjectRegex;
    }
    
    private Pattern subjectMatchingPattern = null;
    
    private Pattern getSubjectMatchingPattern() {
        if (subjectMatchingPattern == null && subjectMatchingRegex != null) {
            subjectMatchingPattern = Pattern.compile(subjectMatchingRegex);
        }
        
        return subjectMatchingPattern;
    }
    
    private XMLSignature signature = null;
    
    private X509Certificate[] certificateChain;
    
    public void initEnvelopingSignature(InputStream is) 
    throws XMLSignatureException, XMLSecurityException, SAXException, IOException {
        try {
            initEnvelopingSignature(builderFactory.newDocumentBuilder().parse(is));
        } catch (ParserConfigurationException e) {
            throw new RuntimeException("DocumentBuilder creation failed; should never happen");
        }
    }
    
    public void initEnvelopingSignature(Document d) 
    throws XMLSignatureException, XMLSecurityException {
        signature = new XMLSignature(d.getDocumentElement(), null);
        certificateChain = null;
    }

    public ObjectContainer[] getObjectContainers() throws VerificationException {
        if (signature == null) {
            throw new UnsupportedOperationException("initXXX() must be called first");
        }

        ObjectContainer[] objectContainers = 
            new ObjectContainer[signature.getObjectLength()];
        for (int i=0; i<signature.getObjectLength(); i++) {
            objectContainers[i] = signature.getObjectItem(i);
        }
        
        return objectContainers;
    }
    
    public Element getObjectElement(String id) throws VerificationException {
        ObjectContainer[] objectContainers = getObjectContainers();
        
        for (int i=0; i<objectContainers.length; i++) {
            ObjectContainer each = objectContainers[i];
            String eachId = each.getElement().getAttribute("Id");
            if (id.equals(eachId)) {
                return each.getElement();
            }
        }
        
        return null;
    }
    
    public X509Certificate[] getCertificateChain() throws VerificationException {
        if (signature == null) {
            throw new UnsupportedOperationException("initXXX() must be called first");
        }

        if (certificateChain == null) {
            KeyInfo ki = signature.getKeyInfo();
    
            // Only work with X509Data sections
            if (!ki.containsX509Data()) {
                throw new UnsupportedOperationException("Signature contains no X509Data");
            }
            
            try {
                // Build the certificate chain
                X509Data x509Data = ki.itemX509Data(0);
                certificateChain = new X509Certificate[x509Data.lengthCertificate()];
                
                for (int i=0; i<x509Data.lengthCertificate(); i++) {
                    certificateChain[i] = x509Data.itemCertificate(i).getX509Certificate();
                }
            } catch (XMLSecurityException e) {
                throw new VerificationException("Error while reading X.509 data from XMLDSig", e);
            }
        }
        
        return certificateChain;
    }
    
    public boolean verify() throws VerificationException {
        try {
            return signature.checkSignatureValue(getCertificateChain()[0]);
        } catch (XMLSignatureException e) {
            throw new VerificationException("XML signature algorithm failed");
        }
    }

    private X509CRLHelper crlHelper;
    
    public void setCrlHelper(X509CRLHelper crlHelper) {
        this.crlHelper = crlHelper;
    }
    
    private OCSPHelper ocspHelper;
    
    public void setOcspHelper(OCSPHelper ocspHelper) {
        this.ocspHelper = ocspHelper;
    }

    private String keyUsageRestrictions;
    
    public void setKeyUsageRestrictions(String keyUsageRestrictions) {
        this.keyUsageRestrictions = keyUsageRestrictions;
    }
    
    public boolean isValid() throws VerificationException, NetworkAccessException {
        X509Certificate certificate = getCertificateChain()[0];
        String subjectName = certificate.getSubjectX500Principal().getName();
        
        try {
            certificate.checkValidity();
        } catch (CertificateExpiredException ignored) {
            return false;
        } catch (CertificateNotYetValidException ignored) {
            return false;
        }
        
        if (    getSubjectMatchingPattern() != null &&
                !getSubjectMatchingPattern().matcher(subjectName).matches()) {
            return false;
        }

        if (    keyUsageRestrictions != null &&
                !KeyUsageHelper.validateKeyUsage(certificate, keyUsageRestrictions)) {
            return false;
        }
        
        if (crlHelper != null && !crlHelper.isValid(certificate)) {
            logger.warn("CRL validation failed");
            
            return false;
        }
        
        if (ocspHelper != null && !ocspHelper.isValid(certificate)) {
            logger.warn("OCSP validation failed");
            
            return false;
        }
        
        return true;
    }
    
    private Set trustAnchors = null;
    
    public void setTrustAnchors(Set trustAnchors) {
        this.trustAnchors = trustAnchors;
    }
    
    public boolean isCertificatePathValid() throws VerificationException {
        if (trustAnchors == null) {
            throw new ConfigurationException("TrustAnchors must be set");
        }
        
        try {
            PKIXParameters parameters = new PKIXParameters(trustAnchors);
            parameters.setRevocationEnabled(false);
    
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            CertPath certPath = cf.generateCertPath(Arrays.asList(getCertificateChain()));
            
            CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
            PKIXCertPathValidatorResult res = (PKIXCertPathValidatorResult)
                    cpv.validate(certPath, parameters);
            
            logger.debug("Certificate path validation succeeded; result=" + res.toString());
            
            return true;
        } catch (CertPathValidatorException e) {
            logger.info("Certificate path validation failed", e);
            return false;
        } catch (InvalidAlgorithmParameterException e) {
            throw new ConfigurationException("PKIX algorithm not found; should not happen");
        } catch (CertificateException e) {
            throw new ConfigurationException("X.509 certificate factory not found; should not happen");
        } catch (NoSuchAlgorithmException e) {
            throw new ConfigurationException("PKIX algorithm not found; should not happen");
        }
    }
    
}
