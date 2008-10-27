package gr.ageorgiadis.util.ini;

import gr.ageorgiadis.security.BrowserKeyStoreFactory.ProfileIniContentHandler;
import gr.ageorgiadis.util.ini.Parser.MalformedException;

import java.io.InputStream;
import java.util.logging.Logger;

import junit.framework.TestCase;

public class ParserTest extends TestCase {

	public void testParser() throws MalformedException {
		Logger.getLogger(ParserTest.class.getName()).fine("Test ...");
		
		InputStream is = this.getClass().getResourceAsStream("/profiles.ini");
		ProfileIniContentHandler mch = new ProfileIniContentHandler();
		Parser p = new Parser();
		p.setContentHandler(mch);
		p.parse(is);
		
		assertTrue(mch.isRelative());
		assertEquals("Profiles/akuyoa9k.default", mch.getDefaultProfilePath());
	}
	
}
