package gr.ageorgiadis.util;

public class HexStringHelper {

	private HexStringHelper() { }
	
	public static final String toHexString(byte[] bytes) {
		StringBuilder sb = new StringBuilder();
		
		for (int i=0; i<bytes.length;i++) {
		    String temp = Integer.toHexString(0xFF & bytes[i]);
		    // Take care of bytes 0x00 - 0x0F
		    if (temp.length() < 2) {
		    	sb.append("0");
		    }
		    sb.append(temp);
		}
		
		return sb.toString();
	}
	
	public static final String toHexString(byte[] bytes, boolean toUpperCase) {
		return toUpperCase?toHexString(bytes).toUpperCase():toHexString(bytes);
	}
	
}
