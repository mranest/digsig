// dsapplet.js

// BrowserDetect script
// Kudos to: http://www.quirksmode.org/js/detect.html
//
var BrowserDetect = {
	init: function () {
		this.browser = this.searchString(this.dataBrowser) || "An unknown browser";
		this.version = this.searchVersion(navigator.userAgent)
			|| this.searchVersion(navigator.appVersion)
			|| "an unknown version";
		this.OS = this.searchString(this.dataOS) || "an unknown OS";
	},
	searchString: function (data) {
		for (var i=0;i<data.length;i++)	{
			var dataString = data[i].string;
			var dataProp = data[i].prop;
			this.versionSearchString = data[i].versionSearch || data[i].identity;
			if (dataString) {
				if (dataString.indexOf(data[i].subString) != -1)
					return data[i].identity;
			}
			else if (dataProp)
				return data[i].identity;
		}
	},
	searchVersion: function (dataString) {
		var index = dataString.indexOf(this.versionSearchString);
		if (index == -1) return;
		return parseFloat(dataString.substring(index+this.versionSearchString.length+1));
	},
	dataBrowser: [
		{ 	string: navigator.userAgent,
			subString: "OmniWeb",
			versionSearch: "OmniWeb/",
			identity: "OmniWeb"
		},
		{
			string: navigator.vendor,
			subString: "Apple",
			identity: "Safari"
		},
		{
			prop: window.opera,
			identity: "Opera"
		},
		{
			string: navigator.vendor,
			subString: "iCab",
			identity: "iCab"
		},
		{
			string: navigator.vendor,
			subString: "KDE",
			identity: "Konqueror"
		},
		{
			string: navigator.userAgent,
			subString: "Firefox",
			identity: "Firefox"
		},
		{
			string: navigator.vendor,
			subString: "Camino",
			identity: "Camino"
		},
		{		// for newer Netscapes (6+)
			string: navigator.userAgent,
			subString: "Netscape",
			identity: "Netscape"
		},
		{
			string: navigator.userAgent,
			subString: "MSIE",
			identity: "Explorer",
			versionSearch: "MSIE"
		},
		{
			string: navigator.userAgent,
			subString: "Gecko",
			identity: "Mozilla",
			versionSearch: "rv"
		},
		{ 		// for older Netscapes (4-)
			string: navigator.userAgent,
			subString: "Mozilla",
			identity: "Netscape",
			versionSearch: "Mozilla"
		}
	],
	dataOS : [
		{
			string: navigator.platform,
			subString: "Win",
			identity: "Windows"
		},
		{
			string: navigator.platform,
			subString: "Mac",
			identity: "Mac"
		},
		{
			string: navigator.platform,
			subString: "Linux",
			identity: "Linux"
		}
	]

};
BrowserDetect.init();

// The official workaround for by passing the 'Press SPACEBAR or ENTER to activate and use this control'
// message of Internet Explorer. formId is optional.
//
// TODO Detect whether http: or https: protocol is in use, and adjust the protocol on the pluginspage URL accordingly
function printAppletDeclaration(width, height, formId) {
	if (BrowserDetect.browser == 'Explorer') {
		document.write('<object id="dsigApplet" classid="clsid:CAFEEFAC-0016-0000-0000-ABCDEFFEDCBA"');
		document.write('		codebase="http://java.sun.com/update/1.6.0/jinstall-6-windows-i586.cab"');
		document.write('        width="' + width + '" height="' + height + '">');
		document.write('	<param name="code" value="gr.ageorgiadis.signature.DSApplet.class" />');
		document.write('	<param name="archive" value="../../target/dsig-applet-jarjar.jar" />');
		document.write('	<param name="mayscript" value="true" />');
		if (typeof formId != 'undefined') {
			document.write('	<param name="formId" value="' + formId + '" />');
		}
		document.write('	<param name="flags" value="!unselectedRadioIncluded" />');
		document.write('	<param name="plaintextElement" value="plaintext" />');
		document.write('	<param name="serialNumberElement" value="serialNumber" />');
		document.write('	<param name="signatureElement" value="signature" />');
		document.write('</object>');
	} else {
		document.write('<embed  id="dsigApplet" code="gr.ageorgiadis.signature.DSApplet.class" archive="../../target/dsig-applet-jarjar.jar"');
		document.write('        width="' + width + '" height="' + height + '"');
		document.write('		type="application/x-java-applet;version=1.6"');
		document.write('		pluginspage="http://java.com/en/download/index.jsp"');
		document.write('		mayscript="true"');
		if (typeof formId != 'undefined') {
			document.write('		formId="' + formId + '"');
		}
		document.write('		flags="!unselectedRadioIncluded"');
		document.write('		plaintextElement="plaintext"');
		document.write('		serialNumberElement="serialNumber"');
		document.write('		signatureElement="signature">');
		document.write('</embed>');
	}
}