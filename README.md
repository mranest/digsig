digsig
======

Digital Signature tools: an applet and a verifier,
enabling an end-to-end digital signature worlflow. The exact algorithm
used is configurable, as is the way the plaintext is constructed.

Although the applet is running in the JRE's applet sandbox (portable
across a number of platforms), proper access to a certificate store
limits its use mainly to IE on Windows. Chrome and Opera also work, but
the certificate store accessed is Windows certificate store.

Firefox does not work anymore!
