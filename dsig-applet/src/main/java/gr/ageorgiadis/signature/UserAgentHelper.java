package gr.ageorgiadis.signature;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import netscape.javascript.JSObject;

/**
 * <p>UserAgentHelper class is used to determine the browser where the applet 
 * is used at runtime, through use of the navigator.userAgent JavaScript.
 * Sample user agent lines:</p>
 * <ul>
 * <li><b>Safari on Windows</b>: Mozilla/5.0 (Windows; U; Windows NT 5.1; el) AppleWebKit/522.15.5 (KHTML, like Gecko) Version/3.0.3 Safari/522.15.5</li>
 * <li><b>MSIE</b>: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; InfoPath.1; .NET CLR 2.0.50727)</li>
 * <li><b>Firefox on Windows</b>: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.9) Gecko/20071025 Firefox/2.0.0.9</li>

 * @author AGeorgiadis
 */
public class UserAgentHelper implements BrowserHelper {
	
	private Map<String, String> nameVersionMap = null;
	
	private Map<String, Set<String>> nameAttributesMap = null;
	
	public UserAgentHelper() { }
	
	public Set<String> getNames() {
		return nameVersionMap.keySet();
	}
	
	public Set<String> getAttributes(String name) {
		return nameAttributesMap.get(name);
	}
	
	public void initialize(JSObject win) {
		String userAgentLine = win.eval("navigator.userAgent").toString();
		initialize(userAgentLine);
	}
	
	public void initialize(String userAgentLine) {
		nameVersionMap = new HashMap<String, String>();
		nameAttributesMap = new HashMap<String, Set<String>>();
		
		Pattern p = Pattern.compile(" ?([^/]*)/([^ ]*)( [(]([^)]*)[)])?");
		Matcher m = p.matcher(userAgentLine);
		while (m.find()) {
			String name = m.group(1);
			String version = m.group(2);
			nameVersionMap.put(name, version);

			String semicolonDelimitedAttributes = m.group(4);
			if (semicolonDelimitedAttributes != null) {
				String[] attributes = semicolonDelimitedAttributes.split(";");
				for (int i=0; i<attributes.length; i++) {
					attributes[i] = attributes[i].trim();
				}
				
				nameAttributesMap.put(name, new HashSet<String>(Arrays.asList(attributes)));
			}
		}
	}
	
	public boolean isSafari() {
		return getNames().contains("Safari");
	}
	
	public boolean isMsie() {
		if (!getNames().contains("Mozilla") || getAttributes("Mozilla").isEmpty()) {
			return false;
		}
		
		for (String attribute : getAttributes("Mozilla")) {
			if (attribute.startsWith("MSIE")) {
				return true;
			}
		}
		
		return false;
	}
	
	public boolean isMozilla() {
		return getNames().contains("Gecko");
	}
	
	public BrowserHelper.Browser getBrowser() {
		if (isSafari()) {
			return BrowserHelper.Browser.Safari;
		}
		if (isMsie()) {
			return BrowserHelper.Browser.Msie;
		}
		if (isMozilla()) {
			return BrowserHelper.Browser.Mozilla;
		}
		
		return BrowserHelper.Browser.Other;
	}
	
}
