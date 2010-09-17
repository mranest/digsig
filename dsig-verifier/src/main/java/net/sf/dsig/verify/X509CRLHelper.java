/*
 * Copyright 2007-2010 Anestis Georgiadis
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
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.httpclient.HostConfiguration;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERString;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

/**
 * A helper class that encapsulates CRL checking logic
 * 
 * @author <a href="mailto:mranest@iname.com">Anestis Georgiadis</a>
 */
public class X509CRLHelper {

	private static final String OID_CRLDISTRIBUTIONPOINTS = "2.5.29.31";
	
	private static final Log logger = LogFactory.getLog(X509CRLHelper.class);
	
	/** A map from URI to LastModified String, for use in cached CRL lists */
	Map uriNextUpdateMap = new HashMap();
	
	/** A map from URI to CRL list */
	Map uriX509CrlMap = new HashMap();
	
	// Two previous maps are package-scoped, in order to facilitate unit tests
	
	private String proxyHost;
	
	public void setProxyHost(String proxyHost) {
		this.proxyHost = proxyHost;
	}
	
	private int proxyPort = -1;
	
	public void setProxyPort(int proxyPort) {
		this.proxyPort = proxyPort;
	}
	
	private String defaultCrlDistributionPoint = null;;
	
	public void setDefaultCrlDistributionPoint(String defaultCrlDistributionPoint) {
		this.defaultCrlDistributionPoint = defaultCrlDistributionPoint;
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

	/**
	 * Validate a certificate using the CRL
	 * 
	 * @param certificate an {@link X509Certificate} object
	 * @return true if the certificate is valid; false otherwise
	 * @throws NetworkAccessException when any network access issues occur
	 * @throws VerificationException when an error occurs while parsing the CRL
	 */
	public boolean isValid(X509Certificate certificate) 
	throws NetworkAccessException, VerificationException {
		
		// First try finding the CRL distribution point in the X.509 certificate
		String uriAsString = X509CRLHelper.getCRLDistributionPointUri(certificate);
		
		// If not found, try falling back to the default
		if (uriAsString == null) {
			uriAsString = defaultCrlDistributionPoint;
		}
		
		// If still null, bail out
		if (uriAsString == null) {
			throw new ConfigurationException("CRL DistributionPoint not found on certificate, and no default set");
		}
		
		return !getX509CRL(uriAsString).isRevoked(certificate);
	}
	
	private Object mutex = new Object();

	private HttpClient client = new HttpClient(new MultiThreadedHttpConnectionManager());
	
	/**
	 * Retrieve the CRL
	 * 
	 * @param distributionPointUriAsString the distribution point URI
	 * @return the {@link X509CRL} object
	 * @throws NetworkAccessException when any network access issues occur
	 * @throws VerificationException when an error occurs while parsing the CRL
	 */
	public X509CRL getX509CRL(String distributionPointUriAsString) 
	throws NetworkAccessException, VerificationException {
		synchronized (mutex) {
			Date nextUpdate = (Date) uriNextUpdateMap.get(distributionPointUriAsString);
			if (	nextUpdate != null &&
					nextUpdate.after(new Date())) {
				logger.debug("Returning cached X509CRL" +
						"; distributionPoint=" + distributionPointUriAsString +
						", nextUpdate=" + nextUpdate);
				return (X509CRL) uriX509CrlMap.get(distributionPointUriAsString);
			}

			HostConfiguration config = getHostConfiguration();
			
			GetMethod get = new GetMethod(distributionPointUriAsString);
			try {
				client.executeMethod(config, get);
				
				logger.debug("HTTP GET executed" + 
						"; distributionPointUri=" + distributionPointUriAsString +
						", statusLine=" + get.getStatusLine());
						
				if (get.getStatusCode() != HttpStatus.SC_OK) {
					throw new NetworkAccessException("HTTP GET failed; statusLine=" + get.getStatusLine());
				}
				
				InputStream is = get.getResponseBodyAsStream();
				
				X509CRL crl = null;
				try {
					crl = (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(is);
				} catch (CertificateException e) {
					throw new ConfigurationException("X.509 certificate factory missing");
				}
				
				uriNextUpdateMap.put(
						distributionPointUriAsString, 
						crl.getNextUpdate());
				uriX509CrlMap.put(
						distributionPointUriAsString, 
						crl);
				
				return crl;
			} catch (IOException e) {
				throw new NetworkAccessException("I/O error occured", e);
			} catch (CRLException e) {
				throw new VerificationException("Error while following CRL protocol", e);
			} finally {
				get.releaseConnection();
			}
		}
	}
	
	/**
	 * Retrieve the CRL URI distribution point from an X.509 certificate, using
	 * the 2.5.29.31 extension value
	 * 
	 * @param certificate an {@link X509Certificate} object
	 * @return a String containing the URI of the CRL distribution point, or
	 * null if none can be found
	 */
	public static String getCRLDistributionPointUri(X509Certificate certificate) {
		byte[] derCdpBytes = certificate.getExtensionValue(OID_CRLDISTRIBUTIONPOINTS);

		if (derCdpBytes == null) {
			return null;
		}
		
		try {
			ASN1InputStream ais = new ASN1InputStream(derCdpBytes);
			DEROctetString dos = (DEROctetString) ais.readObject();
			ais.close();
			
			ais = new ASN1InputStream(dos.getOctets());
			DERSequence seq = (DERSequence) ais.readObject();
			ais.close();
			
			CRLDistPoint cdp = new CRLDistPoint(seq);
			
			for (int i=0; i<cdp.getDistributionPoints().length; i++) {
				DistributionPoint dp = cdp.getDistributionPoints()[i];
				DistributionPointName dpn = dp.getDistributionPoint();
				GeneralNames gns = (GeneralNames) dpn.getName();
				for (int j=0; j<gns.getNames().length; j++) {
					GeneralName gn = gns.getNames()[j];
					if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
						return ((DERString) gn.getName()).getString();
					}
				}
			}
		} catch (IOException e) {
			logger.warn("ASN.1 decoding failed; will fall back to default CRL DistributionPoint, if set");
		}

		return null;
	}
	
}
