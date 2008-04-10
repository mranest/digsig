package gr.ageorgiadis.util;

import java.lang.reflect.InvocationTargetException;

import org.apache.commons.beanutils.BeanUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class FlagsHelper {
	
	private static final Log logger = LogFactory.getLog(FlagsHelper.class);

	/**
	 * Take a comma-delimited list of flags and set the corresponding
	 * properties on the bean Object to true, following JavaBean
	 * conventions. If the name is prepended with '!' set it to false.
	 * @param bean
	 * @param flags
	 */
	public static void setFlags(Object bean, String flags) {
		if (flags == null) {
			return;
		}
		
		for (String flag : flags.split(",")) {
			try {
				if (flag.startsWith("!")) {
					BeanUtils.setProperty(bean, flag.substring(1), "false");
				} else {
					BeanUtils.setProperty(bean, flag, "true");
				}
			} catch (IllegalAccessException e) {
				logger.warn("IllegalAccessException raised", e);
			} catch (InvocationTargetException e) {
				logger.warn("InvocationTargetException raised", e);
			}
		}
	}
	
}
