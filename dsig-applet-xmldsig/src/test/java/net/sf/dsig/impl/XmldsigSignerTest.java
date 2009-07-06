package net.sf.dsig.impl;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.junit.Test;
import org.w3c.dom.Document;

public class XmldsigSignerTest {

	@Test
	public void testSign() throws Exception {
		KeyStore ks = KeyStore.getInstance("pkcs12");
		ks.load(getClass().getResourceAsStream("/sample.pfx"), "123456".toCharArray());
		
		// Only one alias expected
		String alias = ks.aliases().nextElement();
		PrivateKey privateKey = (PrivateKey) ks.getKey(alias, "123456".toCharArray());
		Certificate[] certificates = ks.getCertificateChain(alias);
		X509Certificate[] certificateChain = new X509Certificate[certificates.length];
		int pos = 0;
		for (Certificate c: certificates) {
			certificateChain[pos++] = (X509Certificate) c;
		}
		
		DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
		Document d = db.parse(getClass().getResourceAsStream("/sample.xml"));
		
		XmldsigSigner signer = new XmldsigSigner();
		
		Document sd = signer.sign(privateKey, certificateChain, d);
		
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer t = tf.newTransformer();
//		t.setOutputProperty(OutputKeys.INDENT, "yes");
//		t.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
		
		t.transform(new DOMSource(sd), new StreamResult(System.out));
	}
	
}
