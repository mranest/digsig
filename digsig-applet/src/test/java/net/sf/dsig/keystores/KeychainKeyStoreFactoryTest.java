package net.sf.dsig.keystores;

import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import junit.framework.Assert;

import org.junit.Ignore;
import org.junit.Test;

public class KeychainKeyStoreFactoryTest {

    @Test
    @Ignore("OS incompatibilities")
    public void testFactory() throws Exception {
        KeychainKeyStoreFactory factory = new KeychainKeyStoreFactory();
        KeyStore ks = factory.getKeyStore();
        
        Assert.assertNotNull(ks);
        Enumeration<String> aliases = ks.aliases();

        System.out.println(System.getProperty("os.name"));
        System.out.println(ks.getProvider().getName());
        
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            
            System.out.println("*** Alias: " + alias);
            
            boolean certificateEntry = ks.isCertificateEntry(alias);
            boolean keyEntry = ks.isKeyEntry(alias);
            
            System.out.println(alias + ", " + certificateEntry + ", " + keyEntry);

            if (keyEntry) {
                ks.getKey(alias, "xmouf".toCharArray());
            }
            
            Certificate certificate = ks.getCertificate(alias);
            System.out.println(((X509Certificate) certificate).getSubjectDN().getName());
            
            Certificate[] certificateChain = ks.getCertificateChain(alias);
            System.out.println("Certificate chain length is: " +
                    (certificateChain == null ? null : certificateChain.length));
            
            System.out.println(ks.isKeyEntry(alias) + ":" + (ks.getKey(alias, "password".toCharArray()) != null));
        }
    }
    
}
