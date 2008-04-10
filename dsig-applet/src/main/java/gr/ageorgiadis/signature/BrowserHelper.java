package gr.ageorgiadis.signature;

public interface BrowserHelper {

	enum Browser {
		Safari,
		Msie,
		Mozilla,
		Other
	}
	
	boolean isSafari();
	
	boolean isMsie();
	
	boolean isMozilla();
	
	Browser getBrowser();
	
}
