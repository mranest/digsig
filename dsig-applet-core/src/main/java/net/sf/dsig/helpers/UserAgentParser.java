/*
 * Copyright 2007-2009 Anestis Georgiadis
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

package net.sf.dsig.helpers;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * <p>Sample user agent lines:
 * <ul>
 * <li><b>Safari on Windows</b>: Mozilla/5.0 (Windows; U; Windows NT 5.1; el) AppleWebKit/522.15.5 (KHTML, like Gecko) Version/3.0.3 Safari/522.15.5
 * <li><b>MSIE</b>: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; InfoPath.1; .NET CLR 2.0.50727)
 * <li><b>Firefox on Windows</b>: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.9) Gecko/20071025 Firefox/2.0.0.9
 * <li><b>Chrome on Windows</b>:Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US) AppleWebKit/530.1 (KHTML, like Gecko) Chrome/2.0.169.1 Safari/530.1
 */
public class UserAgentParser {

	private final Map<String, String> nameVersionMap;
	
	private final Map<String, Set<String>> nameAttributesMap;
	
	public Set<String> getNames() {
		return nameVersionMap.keySet();
	}
	
	public String getVersion(String name) {
		return nameVersionMap.get(name);
	}
	
	public Set<String> getAttributes(String name) {
		return nameAttributesMap.get(name);
	}

	public UserAgentParser(String userAgentLine) {
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
	
}
