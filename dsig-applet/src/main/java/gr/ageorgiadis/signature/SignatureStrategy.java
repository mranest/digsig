package gr.ageorgiadis.signature;

import gr.ageorgiadis.signature.xmldsig.XMLDSigStrategy;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * The SigningStrategy class encapsulates the process of signing a form. The
 * base abstract class is a Factory object for the concrete subclasses, and 
 * defines the interface for interaction between the strategy object and 
 * the main applet.
 * 
 * @author ageorgiadis
 */
public abstract class SignatureStrategy {

	protected SignatureStrategy() { }
	
	public abstract void setFlags(String flags);
	
	public abstract void setX509Certificate(X509Certificate certificate);
	
	public abstract void setPrivateKey(PrivateKey privateKey);
	
	public abstract ElementHandler getElementHandler();
	
	public abstract String getSignature() throws SignatureException;
	
	public abstract String getPlaintext() throws SignatureException;
	
	public static SignatureStrategy getInstance(String strategy) 
	throws SignatureException {
		if ("xmldsig".equalsIgnoreCase(strategy)) {
			return new XMLDSigStrategy();
		}
		if ("debug".equalsIgnoreCase(strategy)) {
			return new DebugStrategy();
		}
		
		throw new SignatureException("DSA0010");
	}
	
}
