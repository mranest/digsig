package gr.ageorgiadis.util.ini;

public interface ContentHandler {

	void onStart();
	
	void onSection(String sectionName);
	
	void onEntry(String name, String value);
	
	void onEnd();
	
}
