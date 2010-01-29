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

package net.sf.dsig.helpers;

import junit.framework.Assert;

import org.junit.Test;

public class UserAgentParserTest {

	@Test
	public void testParser() {
		String userAgent = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.9) Gecko/20071025 Firefox/2.0.0.9";
		
		UserAgentParser uap = new UserAgentParser(userAgent);
		Assert.assertTrue(uap.getNames().contains("Mozilla"));
		Assert.assertEquals("5.0", uap.getVersion("Mozilla"));
		Assert.assertEquals(5, uap.getAttributes("Mozilla").size());
		Assert.assertTrue(uap.getAttributes("Mozilla").contains("U"));
	}
	
}
