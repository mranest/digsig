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

package net.sf.dsig.impl;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
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
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

public class XmldsigSigner {

	private DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();

	{
		builderFactory.setNamespaceAware(true);
	}
	
	private XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");
	
	public Document sign(
			PrivateKey signingKey,
			X509Certificate[] certificateChain,
			Document contentDoc) 
	throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, 
	ParserConfigurationException, MarshalException, XMLSignatureException {
		// The Transform object that will contain the C14N method
		Transform refTransform = signatureFactory.newTransform(
				CanonicalizationMethod.EXCLUSIVE, 
				(TransformParameterSpec) null);

		// The Reference object that will contain the form data
		Reference contentRef = signatureFactory.newReference(
				"#formData", 
				signatureFactory.newDigestMethod(DigestMethod.SHA1, null),
				Collections.singletonList(refTransform), null, null);
		
        // Create an XMLObject that corresponds to the formDataDoc DOM Document
        // that we want to include in the Signature
		Node contentNode = contentDoc.getDocumentElement();
        XMLStructure content = new DOMStructure(contentNode);
        XMLObject contentObj = signatureFactory.newXMLObject(
        		Collections.singletonList(content), 
        		"formData", 
        		null, 
        		"UTF-8");

        // Create the SignedInfo structure
        //
		// The CanonicalizationMethod is the algorithm that is used to 
		// canonicalize the SignedInfo element before it is digested 
		// as part of the signature operation.
        //
		// The SignatureMethod is the algorithm that is used to convert the 
		// canonicalized SignedInfo into the SignatureValue
        SignedInfo si = signatureFactory.newSignedInfo(
				signatureFactory.newCanonicalizationMethod(
						CanonicalizationMethod.EXCLUSIVE, 
						(C14NMethodParameterSpec) null),
				signatureFactory.newSignatureMethod(SignatureMethod.RSA_SHA1, null), 
				Collections.singletonList(contentRef));

        KeyInfoFactory kif = signatureFactory.getKeyInfoFactory();
        List<XMLStructure> keyInfoContent = new ArrayList<XMLStructure>();

        // The following code embeds the complete certificate chain
        X509Data x509d = kif.newX509Data(Arrays.asList(certificateChain));
        keyInfoContent.add(x509d);
        
        KeyInfo ki = kif.newKeyInfo(keyInfoContent);

        // Create the XMLSignature object
        XMLSignature signature = signatureFactory.newXMLSignature(
        		si, 
        		ki, 
        		Collections.singletonList(contentObj), 
        		null, 
        		null);
        
        // Create the DOM Document that will receive the signature
        Document signatureDoc = builderFactory.newDocumentBuilder().newDocument();

        DOMSignContext signContext = new DOMSignContext(signingKey, signatureDoc);
        signature.sign(signContext);
        
        return signatureDoc;
	}
	
	
	public Document sign(
			PrivateKey privateKey,
			X509Certificate certificate,
			Document content) 
	throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, 
	ParserConfigurationException, MarshalException, XMLSignatureException {
		return sign(privateKey, new X509Certificate[] { certificate }, content);
	}
	
}
