-injars      target/dsig-applet-xmldsig.jar(!META-INF/maven/**)
-injars      target/dependencies/dsig-applet-core.jar(!net/sf/dsig/impl/**.class,!META-INF/MANIFEST.MF,!META-INF/maven/****)
-injars      target/dependencies/commons-beanutils-core.jar(**.class)
-injars      target/dependencies/commons-codec.jar(**.class)
-injars      target/dependencies/commons-io.jar(**.class)
-injars      target/dependencies/commons-collections.jar(!org/apache/commons/collections/ArrayStack.class,!org/apache/commons/collections/FastHashMap.class,**.class)
-injars      target/dependencies/slf4j-api.jar(**.class)
-injars      target/dependencies/slf4j-ext.jar(**.class)
-injars      target/dependencies/slf4j-jdk14.jar(**.class)
-injars      target/dependencies/jcl-over-slf4j.jar(**.class)
-outjars     target/dsig-applet-complete.jar
-libraryjars <java.home>/lib/rt.jar
-libraryjars <java.home>/lib/plugin.jar
-libraryjars <java.home>/lib/ext/sunpkcs11.jar
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
