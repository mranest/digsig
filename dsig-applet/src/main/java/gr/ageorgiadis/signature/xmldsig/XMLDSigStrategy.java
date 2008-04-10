package gr.ageorgiadis.signature.xmldsig;

import gr.ageorgiadis.signature.ElementHandler;
import gr.ageorgiadis.signature.SignatureException;
import gr.ageorgiadis.signature.SignatureStrategy;
import gr.ageorgiadis.util.FlagsHelper;

import java.io.ByteArrayOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyName;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.codec.binary.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

/* The XML Signature structure:
 * 
<Signature ID?> 
	<SignedInfo>
		<CanonicalizationMethod/>
		<SignatureMethod/>
		(<Reference URI? >
			(<Transforms>)?
			<DigestMethod>
			<DigestValue>
		</Reference>)+
	</SignedInfo>
	<SignatureValue/> 
	(<KeyInfo>)?
	(<Object ID?>)*
</Signature>
 */

public class XMLDSigStrategy extends SignatureStrategy {
	
	private XMLDSigHandler handler = new XMLDSigHandler();

	@Override
	public ElementHandler getElementHandler() {
		return handler;
	}

	@Override
	public void setFlags(String flags) {
		FlagsHelper.setFlags(handler, flags);
	}

	private PrivateKey privateKey = null;
	
	@Override
	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	private X509Certificate x509Certificate = null;
	
	@Override
	public void setX509Certificate(X509Certificate x509Certificate) {
		this.x509Certificate = x509Certificate;
	}

	/**
	 * Create an enveloping XML Signature, using the <code>privateKey</code>
	 * private key and the <code>x509Certificate</code> X.509 certificate. 
	 * The data to sign and envelop are retrieved from the XmlDSigHandler
	 * instance (<code>XmlDSigHandler.getDocument()</code>).
	 * @throws SignatureException 
	 */
	@Override
	public String getSignature() throws SignatureException {
		Document signedDocument = null;
		try {
			signedDocument = sign(
					this.privateKey,
					this.x509Certificate,
					this.handler.getDocument()
				);
		} catch (KeyException e) {
			throw new SignatureException("DSA0012", e);
		} catch (MarshalException e) {
			throw new SignatureException("DSA0013", e);
		} catch (XMLSignatureException e) {
			throw new SignatureException("DSA0014", e);
		}
		
		try {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			Transformer copyTransformer = TransformerFactory.newInstance().newTransformer();
			copyTransformer.transform(
					new DOMSource(signedDocument), 
					new StreamResult(baos));
			return new String(Base64.encodeBase64(baos.toByteArray()));
		} catch (TransformerConfigurationException e) {
			throw new RuntimeException(e);
		} catch (TransformerFactoryConfigurationError e) {
			throw new RuntimeException(e);
		} catch (TransformerException e) {
			throw new SignatureException("DSA0011", e);
		}
	}
	
	@Override
	public String getPlaintext() throws SignatureException {
		try {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			Transformer copyTransformer = TransformerFactory.newInstance().newTransformer();
			copyTransformer.transform(
					new DOMSource(handler.getDocument()), 
					new StreamResult(baos));
			return new String(Base64.encodeBase64(baos.toByteArray()));
		} catch (TransformerConfigurationException e) {
			throw new RuntimeException(e);
		} catch (TransformerFactoryConfigurationError e) {
			throw new RuntimeException(e);
		} catch (TransformerException e) {
			throw new SignatureException("DSA0011", e);
		}
	}
	
	/**
	 * 
	 * @param privKey the private key to use for signing
	 * @param cert the X.509 certificate
	 * @param signDoc the DOM document containing the data to sign
	 * @return a DOM document containing the XML Signature
	 * @throws KeyException if the PublicKey cannot be embedded in the
	 * XMLDSig
	 * @throws XMLSignatureException if an unexpected exception occurs while 
	 * generating the signature
	 * @throws MarshalException if an exception occurs while marshalling
	 */
	public Document sign(
			PrivateKey privKey, 
			X509Certificate cert, 
			Document signDoc) 
	throws KeyException, MarshalException, XMLSignatureException {
        // Preparations for DOM support
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        
        // The XMLSignature factory
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        
        // The Reference object that will contain the form data
        Reference formDataRef;
		try {
			Transform refTransform = fac.newTransform(
					CanonicalizationMethod.EXCLUSIVE, 
					(TransformParameterSpec) null);
			formDataRef = fac.newReference("#formData", 
				fac.newDigestMethod(DigestMethod.SHA1, null),
				Collections.singletonList(refTransform), null, null);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new RuntimeException(e);
		}
        
        // Create an XMLObject that corresponds to the formDataDoc DOM Document
        // that we want to include in the Signature
        Node formDataNode = signDoc.getDocumentElement();
        XMLStructure content = new DOMStructure(formDataNode);
        XMLObject obj = fac.newXMLObject(Collections.singletonList(content), 
        		"formData", null, null);

        // Create the SignedInfo structure
        //
		// The CanonicalizationMethod is the algorithm that is used to 
		// canonicalize the SignedInfo element before it is digested 
		// as part of the signature operation.
        //
		// The SignatureMethod is the algorithm that is used to convert the 
		// canonicalized SignedInfo into the SignatureValue
        SignedInfo si;
		try {
			si = fac.newSignedInfo(
					fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, 
							(C14NMethodParameterSpec) null),
					fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null), 
					Collections.singletonList(formDataRef));
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new RuntimeException(e);
		}

        KeyInfoFactory kif = fac.getKeyInfoFactory();
        List<XMLStructure> keyInfoContent = new ArrayList<XMLStructure>();
        
        // Insert a KeyName, containing the serial number of the certificate
        KeyName kn = kif.newKeyName(cert.getSubjectDN() + ";" + cert.getSerialNumber().toString());
        keyInfoContent.add(kn);
        
        // The following code embeds just the PublicKey
        // KeyValue kv = kif.newKeyValue(cert.getPublicKey());
        // keyInfoContent.add(kv);
        
        // The following code embeds the complete certificate
        X509Data x509d = kif.newX509Data(Collections.singletonList(cert));
        keyInfoContent.add(x509d);
        
        KeyInfo ki = kif.newKeyInfo(keyInfoContent);
        
        // Create the XMLSignature object
        XMLSignature signature = fac.newXMLSignature(si, ki, 
        		Collections.singletonList(obj), null, null);
        
        // Create the DOM Document that will receive the signature
        Document signatureDoc;
		try {
			signatureDoc = dbf.newDocumentBuilder().newDocument();
		} catch (ParserConfigurationException e) {
			throw new RuntimeException(e);
		}
        DOMSignContext dsc = new DOMSignContext(privKey, signatureDoc);
        
        // Sign
        signature.sign(dsc);

        return signatureDoc;
	}

}
