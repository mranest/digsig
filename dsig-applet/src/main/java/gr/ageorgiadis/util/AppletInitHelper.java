package gr.ageorgiadis.util;

import java.applet.Applet;
import java.beans.PropertyDescriptor;

import org.apache.commons.beanutils.BeanUtils;
import org.apache.commons.beanutils.PropertyUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * <p>An auxiliary class to assist during Applet initialization. Through the use
 * of the PropertyUtils class it retrieves run-time parameters and injects
 * them, JavaBean fashion.</p>
 * <p>All methods offered are static./</p>
 * 
 * @author AGeorgiadis
 */
public class AppletInitHelper {
	
	private static final Log logger = LogFactory.getLog(AppletInitHelper.class);

	/**
	 * Private visibility set to default constructor, to avoid erroneous
	 * instantiation of class objects.
	 */
	private AppletInitHelper() { }
	
	public static void init(Applet applet) {
		// Iterate through all the properties declared for the applet class
		PropertyDescriptor[] descriptors = 
			PropertyUtils.getPropertyDescriptors(applet);
		for (PropertyDescriptor descriptor : descriptors) {
			// Check if an applet parameter has been specified; if so, override
			// the value with the one supplied
			if (applet.getParameter(descriptor.getName()) != null) {
				try {
					BeanUtils.setProperty(applet, descriptor.getName(), 
							applet.getParameter(descriptor.getName()));
				} catch (Exception e) {
					logger.fatal("Applet Initialization Error", e);
					throw new AppletInitException("Applet Initialization Error", e);
				}
			}
		}
	}

	private static class AppletInitException extends RuntimeException {
		private static final long serialVersionUID = 1331657180519986590L;
		public AppletInitException(String msg, Throwable t) {
			super(msg, t);
		}
	}
	
}
