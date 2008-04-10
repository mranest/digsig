package gr.ageorgiadis.util.ini;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

public class Parser {

	private ContentHandler contentHandler = null;
	
	public void setContentHandler(ContentHandler contentHandler) {
		this.contentHandler = contentHandler;
	}
	
	public void parse(InputStream is) throws MalformedException {
		if (contentHandler != null) {
			// Wrap the InputStream in a BufferedReader
			BufferedReader br = new BufferedReader(
					new InputStreamReader(is));
			String line = null;
			try {
				while ((line = br.readLine()) != null) {
					String trimmedLine = line.trim();
					// Skip empty lines
					if (trimmedLine == null || trimmedLine.length() == 0) {
						continue;
					}
					// Skip comment lines
					if (trimmedLine.startsWith("'")) {
						continue;
					}
					
					if (trimmedLine.startsWith("[")) {
						// Section
						if (trimmedLine.indexOf(']') == -1) {
							throw new MalformedException("Malformed section; missing right bracket");
						}

						contentHandler.onSection(trimmedLine.substring(1, 
								trimmedLine.indexOf("]")));
					} else {
						// Entry
						if (trimmedLine.indexOf('=') == -1) {
							throw new MalformedException("Malformed entry; missing =");
						}
						
						String name = trimmedLine.substring(0, trimmedLine.indexOf('='));
						String value = null;
						if (trimmedLine.indexOf('\'', trimmedLine.indexOf('=')) == -1) {
							// No comment on the line
							value = trimmedLine.substring(
									trimmedLine.indexOf('=') + 1);
						} else {
							// Comment exists; remove it
							value = trimmedLine.substring(
									trimmedLine.indexOf('=') + 1,
									trimmedLine.indexOf('\'')).trim();
						}
						
						contentHandler.onEntry(name, value);
					}
				}
			} catch (IOException e) {
				throw new MalformedException("I/O error during reading", e);
			}

			try {
				br.close();
			} catch (IOException e) {
				throw new MalformedException("I/O error during closing", e);
			}
		}
		
		try {
			is.close();
		} catch (IOException e) {
			throw new MalformedException("I/O error during closing", e);
		}
	}

	public static class MalformedException extends Exception {
		private static final long serialVersionUID = 7902299455923738808L;
		public MalformedException(String message) { super(message); }
		public MalformedException(String message, Throwable cause) {
			super(message, cause);
		}
	}
	
}
