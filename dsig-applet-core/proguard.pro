-injars      target/dsig-applet-core.jar(!META-INF/maven/**)
-injars      target/dependencies/commons-beanutils-core.jar(**.class)
-injars      target/dependencies/commons-codec.jar(**.class)
-injars      target/dependencies/commons-io.jar(**.class)
-injars      target/dependencies/commons-collections.jar(!org/apache/commons/collections/ArrayStack.class,!org/apache/commons/collections/FastHashMap.class,**.class)
-injars      target/dependencies/slf4j-api.jar(**.class)
-injars      target/dependencies/slf4j-jdk14.jar(**.class)
-injars      target/dependencies/jcl-over-slf4j.jar(**.class)
-outjars     target/dsig-applet-complete.jar
-libraryjars C:/Users/mranest/opt/jdk1.6.0_14/jre/lib/rt.jar
-libraryjars C:/Users/mranest/opt/jdk1.6.0_14/jre/lib/plugin.jar
-libraryjars C:/Users/mranest/opt/jdk1.6.0_14/jre/lib/ext/sunpkcs11.jar
-dontskipnonpubliclibraryclasses
-ignorewarnings
-dontobfuscate
-dontoptimize

-keep public class net.sf.dsig.DSApplet {
	public protected *;
}

-keep public class net.sf.dsig.** {
	public protected *;
}
