package net.sf.dsig.impl;

import java.beans.PropertyDescriptor;

import net.sf.dsig.xmldsig.XmldsigStrategy;
import org.apache.commons.beanutils.PropertyUtils;
import org.junit.Test;

public class XmldsigStrategyTest {

    @Test
    public void testInit() {
        PropertyDescriptor[] descriptors = 
            PropertyUtils.getPropertyDescriptors(new XmldsigStrategy());
        
        for (PropertyDescriptor descriptor: descriptors) {
            System.out.println(descriptor.getName());
        }
        
    }
    
}
