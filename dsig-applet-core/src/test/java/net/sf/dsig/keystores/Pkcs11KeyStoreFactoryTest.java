package net.sf.dsig.keystores;

import org.junit.Test;

public class Pkcs11KeyStoreFactoryTest {

	@Test
	public void testNss() {
		System.loadLibrary("nss3");
	}
	
}
