package net.sf.dsig.verify;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import junit.framework.TestCase;

import org.apache.xml.security.signature.ObjectContainer;
import org.apache.xml.security.utils.Base64;
import org.dom4j.Node;
import org.jaxen.XPath;
import org.jaxen.dom.DOMXPath;
import org.w3c.dom.Attr;
import org.w3c.dom.Element;

public class XmldsigVerifierTest extends TestCase {

    /*
    public void testVerify() throws Exception {
        XmldsigVerifier v = new XmldsigVerifier();
        v.setCrlHelper(X509CRLHelperTest.getCrlHelper());
        v.setOcspHelper(OCSPHelperTest.getOcspHelper());

        try {
            v.isValid();
            fail("Unsupported operation exception not raised");
        } catch (UnsupportedOperationException ignored) {
        }

        v.initEnvelopingSignature(getClass().getResourceAsStream(
                "/sample-xmldsig.xml"));

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) cf
                .generateCertificate(getClass()
                        .getResourceAsStream("/root.cer"));
        TrustAnchor ta = new TrustAnchor(certificate, null);
        Set trustAnchors = new HashSet();
        trustAnchors.add(ta);

        v.setTrustAnchors(trustAnchors);

        // No exceptions expected
        assertTrue(v.isCertificatePathValid());
        assertTrue(v.isValid());

        assertTrue(v.verify());
    }
    */

    private String utf8Signature = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8+PFNpZ25hdHVyZSB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+PFNpZ25lZEluZm8+PENhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3JzYS1zaGExIi8+PFJlZmVyZW5jZSBVUkk9IiNmb3JtRGF0YSI+PFRyYW5zZm9ybXM+PFRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvVHJhbnNmb3Jtcz48RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3NoYTEiLz48RGlnZXN0VmFsdWU+MlBqOFRRaHViZUNhOTBOU2QwUEdwSDVoQXdZPTwvRGlnZXN0VmFsdWU+PC9SZWZlcmVuY2U+PC9TaWduZWRJbmZvPjxTaWduYXR1cmVWYWx1ZT5uMnRZRVRIako2QVE3RmI2ZklLRFpKckNUcTVxMWM3YzBKWnlVZXgvZThxaDRHNTBjSUZuZW9VMWFIZ084azBIekhvY1QxazJaSGdIDQpNbVFVcU5HdTlLeG9icHhhSHJWVXdid2YwMTd2bWJzc3ZSd3dIMEthbERLTDJBNlVBSWNKSTZXOURFMG54clprYW9nNUFSbGxmbWNyDQp3ZXNiYlhqZWgrZlpRVVdPNmxZPTwvU2lnbmF0dXJlVmFsdWU+PEtleUluZm8+PFg1MDlEYXRhPjxYNTA5Q2VydGlmaWNhdGU+TUlJRXBqQ0NCQStnQXdJQkFnSVFHck1IRUhXUGFxVGUzNHNCTDlRNDRUQU5CZ2txaGtpRzl3MEJBUVVGQURDQm5ERUxNQWtHQTFVRQ0KQmhNQ1IxSXhJekFoQmdOVkJBb1RHa1ZHUnlCRmRYSnZZbUZ1YXlCRmNtZGhjMmxoY3lCQkxrVXVNUjh3SFFZRFZRUUxFeFpXWlhKcA0KVTJsbmJpQlVjblZ6ZENCT1pYUjNiM0pyTVI4d0hRWURWUVFMRXhaR1QxSWdWRVZUVkNCUVZWSlFUMU5GVXlCUFRreFpNU1l3SkFZRA0KVlFRREV4MUZSa2NnUlhWeWIySmhibXNnUlhKbllYTnBZWE1nVkVWVFZDQkRRVEFlRncwd09URXdNRFV3TURBd01EQmFGdzB4TURFdw0KTURVeU16VTVOVGxhTUlJQkN6RWVNQndHQTFVRUN4UVZRV3hwWVhNZ0xTQmphSEpwY3kxMFpYTjBaWEl4TVFzd0NRWURWUVFHRXdKSA0KVWpFZk1CMEdBMVVFQ3hRV1JrOVNJRlJGVTFRZ1VGVlNVRTlUUlZNZ1QwNU1XVEV4TUM4R0ExVUVDeFFvVkdWeWJYTWdiMllnZFhObA0KSUdGMElITmxZeTVoWkdGamIyMHVZMjl0TDNKd1lTQW9ZeWt3TXpFak1DRUdBMVVFQ2hRYVJVWkhJRVYxY205aVlXNXJJRVZ5WjJGeg0KYVdGeklFRXVSUzR4RVRBUEJnTlZCQXdVQ0RBd01qWXlPRFk0TVJVd0V3WURWUVFFRXd4RlVFOU9NREF5TmpJNE5qZ3hGVEFUQmdOVg0KQkNvVERFOU9UMDB3TURJMk1qZzJPREVpTUNBR0ExVUVBeE1aVDA1UFRUQXdNall5T0RZNElFVlFUMDR3TURJMk1qZzJPRENCbnpBTg0KQmdrcWhraUc5dzBCQVFFRkFBT0JqUUF3Z1lrQ2dZRUEwQ1dGamwvTzJadldRN09uNDV4M21ScnNPbERKR1J1ZUxUc0tVSjZjSU5Jcw0KWjlqb3A1dlVrMnpuSndNK2kxOVZrQTZhVUhRaVY1TVo0cVZmRHB3ZWs0d1ZRR3NVQzI5TjZFWjJESjR4TlZVaGJRQlVWcXdkNUxmSQ0KMnpCVWcxT1FtaWRWMEc4VmJzR1VqMFRWd0dzenN1L0M5dUc5WFJKUVJybEcvSXFBbG9NQ0F3RUFBYU9DQVhVd2dnRnhNQWtHQTFVZA0KRXdRQ01BQXdDd1lEVlIwUEJBUURBZ1hnTUZzR0ExVWRJQVJVTUZJd053WUxZSVpJQVliNFJRRUhGd0l3S0RBbUJnZ3JCZ0VGQlFjQw0KQVJZYWFIUjBjSE02THk5elpXTXVZV1JoWTI5dExtTnZiUzl5Y0dFd0RRWUxZSVpJQVliNFJRRUhMQUl3Q0FZR0JBQ0xNQUVCTUdJRw0KQTFVZEh3UmJNRmt3VjZCVm9GT0dVV2gwZEhBNkx5OWpjbXd0ZEdWemRDNWhaR0ZqYjIwdVkyOXRMMFZHUjBWMWNtOWlZVzVyUlhKbg0KWVhOcFlYTkJSVVpQVWxSRlUxUlFWVkpRVDFORlUwOU9URmt2VEdGMFpYTjBRMUpNTG1OeWJEQVJCZ2xnaGtnQmh2aENBUUVFQkFNQw0KQjRBd0VRWUtZSVpJQVliNFJRRUdDUVFEQVFIL01CMEdBMVVkSlFRV01CUUdDQ3NHQVFVRkJ3TUNCZ2dyQmdFRkJRY0RCREFZQmdncg0KQmdFRkJRY0JBd1FNTUFvd0NBWUdCQUNPUmdFQk1EY0dDQ3NHQVFVRkJ3RUJCQ3N3S1RBbkJnZ3JCZ0VGQlFjd0FZWWJhSFIwY0Rvdg0KTDI5amMzQXRkR1Z6ZEM1aFpHRmpiMjB1WTI5dE1BMEdDU3FHU0liM0RRRUJCUVVBQTRHQkFGR0s3UG1MMVAyTU53bnNQTVEzOGNrdw0KOTJhNGt1ZVRWbG1vazhRT3hZamp6TGFscjV3anZVck0xQlVmYWJVYjdKOUFvQUdXNkN1N3pDRi85YjNsQWxJT1Q0T2NyLzFWT2FXZw0KcEtvK1gwSHVyWlF0bjZHSDNqV1N3cDB1b3FXSDVBdGpDMlRoRUw3VEdWTzJKVFRRUHE5ejBvMmZVNnY2MFdIUnptb3BuZWlJPC9YNTA5Q2VydGlmaWNhdGU+PFg1MDlDZXJ0aWZpY2F0ZT5NSUlETHpDQ0FwaWdBd0lCQWdJUUtqOW93eDJPakE0OFhGVXcyMDNpbHpBTkJna3Foa2lHOXcwQkFRVUZBREI1TVJRd0VnWURWUVFLDQpFd3RCWkdGamIyMGdVeTVCTGpFZk1CMEdBMVVFQ3hNV1ZtVnlhVk5wWjI0Z1ZISjFjM1FnVG1WMGQyOXlhekVmTUIwR0ExVUVDeE1XDQpSazlTSUZSRlUxUWdVRlZTVUU5VFJWTWdUMDVNV1RFZk1CMEdBMVVFQXhNV1FXUmhZMjl0SUVOc1lYTnpJRElnVkVWVFZDQkRRVEFlDQpGdzB3TmpBNU1qVXdNREF3TURCYUZ3MHhNVEE1TWpReU16VTVOVGxhTUlHY01Rc3dDUVlEVlFRR0V3SkhVakVqTUNFR0ExVUVDaE1hDQpSVVpISUVWMWNtOWlZVzVySUVWeVoyRnphV0Z6SUVFdVJTNHhIekFkQmdOVkJBc1RGbFpsY21sVGFXZHVJRlJ5ZFhOMElFNWxkSGR2DQpjbXN4SHpBZEJnTlZCQXNURmtaUFVpQlVSVk5VSUZCVlVsQlBVMFZUSUU5T1RGa3hKakFrQmdOVkJBTVRIVVZHUnlCRmRYSnZZbUZ1DQpheUJGY21kaGMybGhjeUJVUlZOVUlFTkJNSUdmTUEwR0NTcUdTSWIzRFFFQkFRVUFBNEdOQURDQmlRS0JnUURCa2YyNHRtaldEcUtIDQpFMndnbVlIbTJXVTNiTEM4ZTRVYmREampQRy9mb2l0ZTFtSjhUVGZ3aVZoTm1OUmtXWk96WkRRUVpRSUxRMXpIbG5zQWxaaFhrUjNwDQpOYjJzc3ErYi9pdGpGTlJJY0RRUldEK1d3M0dTZ0tsNmQ2ZmxoZWUrRlU5eEIveGRQdDhWUU9Eci81WmlwTzZkUFpOUjNWM080M2MwDQpEOHQzOHdJREFRQUJvNEdUTUlHUU1CSUdBMVVkRXdFQi93UUlNQVlCQWY4Q0FRQXdPQVlEVlIwZkJERXdMekF0b0N1Z0tZWW5hSFIwDQpjRG92TDJOeWJDMTBaWE4wTG1Ga1lXTnZiUzV1WlhRdll6SjBaWE4wWTJFdVkzSnNNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVJCZ2xnDQpoa2dCaHZoQ0FRRUVCQU1DQVFZd0hRWURWUjBPQkJZRUZNcnMvTi81VnBKS21TcUhFR0RaQ3l5RzhCcjlNQTBHQ1NxR1NJYjNEUUVCDQpCUVVBQTRHQkFLd1ArejdhdnpYYnJWb2NhUXVncURSSXliYnh2WW9CRm9oS2xSNmdKR01BcFdPWHdSMU9waHMyZUlJMjdRdkxwS0ViDQp2SzhlOEdQZitSeFpYaDVDRWNSWHhMcW5Ob0YxQ0VsSU9DQUk0dE9tVURJN2d4L09nTENsVHBnU0g0dGNxMVpreWVWSG5acW45dnlWDQpFeXY5YlE0RlkzdDZYMWsyVXE3MHZXSWU2djRnPC9YNTA5Q2VydGlmaWNhdGU+PFg1MDlDZXJ0aWZpY2F0ZT5NSUlERERDQ0FuV2dBd0lCQWdJUU1GNDYzS3NJUVp3RWtZT0E2NitpNkRBTkJna3Foa2lHOXcwQkFRVUZBRENCOERFTE1Ba0dBMVVFDQpCaE1DVlZNeEZ6QVZCZ05WQkFvVERsWmxjbWxUYVdkdUxDQkpibU11TVVFd1B3WURWUVFMRXpoRGJHRnpjeUF5SUZSRlUxUWdVSFZpDQpiR2xqSUZCeWFXMWhjbmtnUTJWeWRHbG1hV05oZEdsdmJpQkJkWFJvYjNKcGRIa2dMU0JITWpGRE1FRUdBMVVFQ3hNNlZHVnliWE1nDQpiMllnZFhObElHRjBJR2gwZEhCek9pOHZkM2QzTG5abGNtbHphV2R1TG1OdmJTOWpjSE12ZEdWemRHTmhMeUFvWXlrd01qRWZNQjBHDQpBMVVFQ3hNV1ZtVnlhVk5wWjI0Z1ZISjFjM1FnVG1WMGQyOXlhekVmTUIwR0ExVUVDeE1XUm05eUlGUmxjM1FnVUhWeWNHOXpaWE1nDQpUMjVzZVRBZUZ3MHdNakEyTWpZd01EQXdNREJhRncweE5UQTRNVGt5TXpVNU5UbGFNSGt4RkRBU0JnTlZCQW9UQzBGa1lXTnZiU0JUDQpMa0V1TVI4d0hRWURWUVFMRXhaV1pYSnBVMmxuYmlCVWNuVnpkQ0JPWlhSM2IzSnJNUjh3SFFZRFZRUUxFeFpHVDFJZ1ZFVlRWQ0JRDQpWVkpRVDFORlV5QlBUa3haTVI4d0hRWURWUVFERXhaQlpHRmpiMjBnUTJ4aGMzTWdNaUJVUlZOVUlFTkJNSUdmTUEwR0NTcUdTSWIzDQpEUUVCQVFVQUE0R05BRENCaVFLQmdRQ3o5d09FbS9LbDBiVUZFTEszV2dQS0kwNWhuaFlENjJPZEhxa245bVJmeW5ETlcvK3puYlFlDQpFVlZUMHpxditzN0ZKZzYwR0oyL29JUVZSMzROaFdVOU1KOWF5THVyWTBDNDlhUTFteVRZUmYxZUhlSlhQMndnOWxBV2lMTGNvWm5kDQpNN0R4VHZwMktRMElTOC8zWUo1d21RczRORzViVE1obVJDWnFKZjFHUndJREFRQUJveDB3R3pBTEJnTlZIUThFQkFNQ0FRWXdEQVlEDQpWUjBUQkFVd0F3RUIvekFOQmdrcWhraUc5dzBCQVFVRkFBT0JnUUNxMkQ3dEJyR0I4dXRlZ2txQmZ5c1hLNlFhSHl5bXZhc3lZMlZBDQp4SnhZTUpJdC9IbS9PbHRaS0tMVmI2dm9NNktaY1dvbWFnYzY5ZDlnT2NEakk1QnZ4TG1QeHEwOTBRYW01aXFOS1orb2haZENMbFVaDQp4K0sxM3FaQ0RKeTUwT3EwdUNYMzlLcDZHY2VXMGlMdFM1VmRJQzhmY2VVM2NnWWNzT2dHaGJZZmFBPT08L1g1MDlDZXJ0aWZpY2F0ZT48L1g1MDlEYXRhPjwvS2V5SW5mbz48T2JqZWN0IEVuY29kaW5nPSJVVEYtOCIgSWQ9ImZvcm1EYXRhIj48Zm9ybSBpZD0ibWFpbiIgbmFtZT0ibWFpbiI+PGlucHV0IG5hbWU9InBsYWludGV4dCIgdHlwZT0iaGlkZGVuIiB2YWx1ZT0iUEdOdmJTNWxabWN1WldKaGJtdHBibWN1Wm14dmQyUmhkR0V1UTJGeVpGQmhlVzFsYm5SR2JHOTNSR0YwWVQ0S0lDQThZV04wYVc5dVNXUStRMkZ5WkhOVFpYSjJhV05sTG5CaGVVOTBhR1Z5S0NrOEwyRmpkR2x2Ymtsa1Bnb2dJRHh1YjI1alpUNDNNV1UzWldOa1ppMHlPVEkyTFRRMlpUZ3RZVFZrTUMwNVl6VmpaalkwWm1KbE1URThMMjV2Ym1ObFBnb2dJRHh3WVhsdFpXNTBWSGx3WlQ1dmRHaGxja0poYm10RFlYSmtQQzl3WVhsdFpXNTBWSGx3WlQ0S0lDQThaR1ZpYVhSQlkyTnZkVzUwUGpBd01qWXdNREkxTkRFd01qQXdPRFkzTkRnMFBDOWtaV0pwZEVGalkyOTFiblErQ2lBZ1BHUmxZbWwwUVdOamIzVnVkRUpsYm1WbWFXTnBZWEpwWlhNK0NpQWdJQ0E4YzNSeWFXNW5QczZWenFET3FjNmRNREF5TmpJNE5qZ2dUMDVQVFRBd01qWXlPRFk0SU02Z3pwSE9wTTZoTURBeU5qSTROamc4TDNOMGNtbHVaejRLSUNBOEwyUmxZbWwwUVdOamIzVnVkRUpsYm1WbWFXTnBZWEpwWlhNK0NpQWdQR055WldScGRFTmhjbVErTkRVMU5qUTBNREF3TVRrME5ETXlPVHd2WTNKbFpHbDBRMkZ5WkQ0S0lDQThZVzF2ZFc1MFBqVXhNREE4TDJGdGIzVnVkRDRLSUNBOFkzVnljbVZ1WTNrK1JWVlNQQzlqZFhKeVpXNWplVDRLSUNBOFltVnVaV1pwWTJsaGNubE9ZVzFsUG5OaFpHRmtjMkZrYzJSaFBDOWlaVzVsWm1samFXRnllVTVoYldVK0NpQWdQRzkwYUdWeVFtRnVhME5oY21ST1lXMWxQbk5rWVhOa2MyUmhQQzl2ZEdobGNrSmhibXREWVhKa1RtRnRaVDRLSUNBOFltRnVhMDVoYldVK1EwbFVTVUpCVGtzZ1RpNUJMand2WW1GdWEwNWhiV1UrQ2lBZ1BHSmhibXREYjJSbFBrTkpWRWxIVWtGQldGaFlQQzlpWVc1clEyOWtaVDRLSUNBOFpYaHdaVzV6WlhNK01Ud3ZaWGh3Wlc1elpYTStDaUFnUEdGalkyOTFiblJVZVhCbFBzNmZ6cWpPbGM2cHpxTXRJTTZSenFUT244NmF6cC9Pb3p3dllXTmpiM1Z1ZEZSNWNHVStDand2WTI5dExtVm1aeTVsWW1GdWEybHVaeTVtYkc5M1pHRjBZUzVEWVhKa1VHRjViV1Z1ZEVac2IzZEVZWFJoUGc9PSIvPjxzZWxlY3QgbXVsdGlwbGU9ImZhbHNlIiBuYW1lPSJjZXJ0aWZpY2F0ZXMiPjxvcHRpb24gc2VsZWN0ZWQ9InRydWUiIHZhbHVlPSIgKGNocmlzLXRlc3RlcjEpIC0xNzQ3NjkyMSI+Y2hyaXMtdGVzdGVyMSAtIE9OT00wMDI2Mjg2OCBFUE9OMDAyNjI4Njg8L29wdGlvbj48L3NlbGVjdD48aW5wdXQgbmFtZT0ial9pZDkwIiB0eXBlPSJ0ZXh0IiB2YWx1ZT0iIi8+PC9mb3JtPjwvT2JqZWN0PjwvU2lnbmF0dXJlPg==";
    
    public void testUSignature() throws Exception {
        InputStream is = new ByteArrayInputStream(Base64.decode(utf8Signature.getBytes()));
        
        XmldsigVerifier v = new XmldsigVerifier();
//      v.setCrlHelper(X509CRLHelperTest.getCrlHelper());
//      v.setOcspHelper(OCSPHelperTest.getOcspHelper());

        v.initEnvelopingSignature(is);
        
        ObjectContainer[] objectContainers = v.getObjectContainers();
        for (int i=0; i<objectContainers.length; i++) {
            ObjectContainer each = objectContainers[i];
            Element element = each.getElement();
            
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.transform(new DOMSource(element), new StreamResult(System.out));
            System.out.println();
            
            XPath xpath = new DOMXPath("//ds:input[@name='plaintext']/@value");
            xpath.addNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
            Attr valueAttr = (Attr) xpath.selectSingleNode(element);
            
            System.out.println(valueAttr.getTextContent());
        }
        
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) cf
                .generateCertificate(getClass()
                        .getResourceAsStream("/root.cer"));
        TrustAnchor ta = new TrustAnchor(certificate, null);
        Set trustAnchors = new HashSet();
        trustAnchors.add(ta);

        v.setTrustAnchors(trustAnchors);

//      assertTrue(v.isCertificatePathValid());
//      assertTrue(v.isValid());
//
//      assertTrue(v.verify());
    }

}
