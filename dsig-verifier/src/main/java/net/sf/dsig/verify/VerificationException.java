package net.sf.dsig.verify;

public class VerificationException extends Exception {

	private static final long serialVersionUID = -1271942920833897881L;

	public VerificationException() { }
	
	public VerificationException(String message) {
		super(message);
	}
	
	public VerificationException(String message, Throwable cause) {
		super(message, cause);
	}
	
}
