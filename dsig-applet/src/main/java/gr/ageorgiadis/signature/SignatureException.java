package gr.ageorgiadis.signature;

public class SignatureException extends Exception {
	
	private static final long serialVersionUID = -5157609512668671709L;
	
	private final String errorCode;
	
	public String getErrorCode() {
		return errorCode;
	}
	
	public SignatureException(String errorCode) {
		this.errorCode = errorCode;
	}
	
	public SignatureException(String errorCode, Throwable cause) {
		super(cause);
		this.errorCode = errorCode;
	}
	
}