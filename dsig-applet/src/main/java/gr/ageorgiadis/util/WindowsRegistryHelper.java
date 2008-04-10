package gr.ageorgiadis.util;

import gr.ageorgiadis.util.WindowsRegistryHelper.RegistryValue.Type;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * Kudos to:
 * http://saloon.javaranch.com/cgi-bin/ubb/ultimatebb.cgi?ubb=get_topic&f=34&t=006923
 * 
 * @author AGeorgiadis
 */
public class WindowsRegistryHelper {

	private static final String REGQUERY_UTIL = "reg query ";

	private ThreadReader executeRegQuery(String key) 
	throws IOException {
		if (!key.startsWith("\"") && key.indexOf(' ') != -1) {
			key = "\"" + key + "\"";
		}
		
		Process p = Runtime.getRuntime().exec(REGQUERY_UTIL + key);
		ThreadReader stdoutReader = new ThreadReader(p.getInputStream());
		stdoutReader.start();
		try {
			p.waitFor();
			stdoutReader.join();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		
		return stdoutReader;
	}
	
	public Collection<String> getKeys(String key) 
	throws IOException {
		ThreadReader stdoutReader = executeRegQuery(key);
		
		Set<String> keys = new HashSet<String>();
		
		BufferedReader br = stdoutReader.getBufferedReader();
		String line = null;
		boolean firstKeyFound = false;
		while ((line = br.readLine()) != null) {
			// Skip empty/comment lines
			if (line.startsWith("!")) {
				continue;
			}
			if (line.trim().length() == 0) {
				continue;
			}
			
			// Skip intended lines; these are values
			if (!line.startsWith("    ")) {
				if (firstKeyFound) {
					keys.add(line);
				} else {
					firstKeyFound = true;
				}
			}
		}
		
		return keys;
	}
	
	private Pattern valuePattern = Pattern.compile("    (.*)\t(.*)\t(.*)");
	
	public Map<String, RegistryValue> getValues(String key) 
	throws IOException {
		ThreadReader stdoutReader = executeRegQuery(key);
		
		Map<String, RegistryValue> values = new HashMap<String, RegistryValue>();
		
		BufferedReader br = stdoutReader.getBufferedReader();
		String line = null;
		while ((line = br.readLine()) != null) {
			// Skip empty/comment lines
			if (line.startsWith("!")) {
				continue;
			}
			if (line.trim().length() == 0) {
				continue;
			}
			
			// Skip intended lines; these are values
			if (line.startsWith("    ")) {
				Matcher m = valuePattern.matcher(line);
				if (m.find()) {
					String name = m.group(1);
					String type = m.group(2);
					String value = m.group(3);
					
					values.put(name, new RegistryValue(
							Type.valueOf(type),
							value));
				}
			}
		}
		
		return values;
	}

	public class ThreadReader extends Thread {

		private final InputStream is;

		private final ByteArrayOutputStream baos = new ByteArrayOutputStream();

		public ThreadReader(InputStream is) {
			this.is = is;
		}

		private boolean failed = false;

		public boolean isFailed() {
			return failed;
		}

		@Override
		public void run() {
			try {
				int c;
				while ((c = is.read()) != -1) {
					baos.write(c);
				}
			} catch (IOException e) {
				failed = true;
			}
		}

		public BufferedReader getBufferedReader() {
			return new BufferedReader(new StringReader(toString()));
		}
		
		@Override
		public String toString() {
			return new String(baos.toByteArray());
		}

	}

	public static class RegistryValue {
		public enum Type {
			REG_SZ,
			REG_BINARY,
			REG_DWORD
		}
		
		private Type type;
		
		public Type getType() {
			return type;
		}
		
		private String value;
		
		public String getValue() {
			return value;
		}
		
		public RegistryValue(Type type, String value) {
			this.type = type;
			this.value = value;
		}
		
		@Override
		public String toString() {
			return type + ": " + value;
		}
	}
	
}
