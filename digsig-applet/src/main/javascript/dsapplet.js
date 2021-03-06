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

var DSApplet = function(jarUrl) {
	this.jarUrl = jarUrl;
	this.protocol = (document.location.protocol == 'https:') ? 'https:' : 'http:';
};

DSApplet.prototype = {
	setFormId: function (formId) {
		this.formId = formId;
	},
	setBackgroundColor: function (backgroundColor) {
		this.backgroundColor = backgroundColor;
	},
	setSuccessJSFunction: function (successJSFunction) {
		this.successJSFunction = successJSFunction;
	},
	setErrorJSFunction: function (errorJSFunction) {
		this.errorJSFunction = errorJSFunction;
	},
	setNoCertificatesJSFunction: function (noCertificatesJSFunction) {
		this.noCertificatesJSFunction = noCertificatesJSFunction;
	},
	setStartedJSFunction: function (startedJSFunction) {
		this.startedJSFunction = startedJSFunction;
	},
	setExpirationDateChecked: function (expirationDateChecked) {
		this.expirationDateChecked = expirationDateChecked;
	},
	setSubjectMatchingRegex: function (subjectMatchingRegex) {
		this.subjectMatchingRegex = subjectMatchingRegex;
	},
	setIssuerMatchingRegex: function (issuerMatchingRegex) {
		this.issuerMatchingRegex = issuerMatchingRegex;
	},
	setSubjectNameRegex: function (subjectNameRegex) {
		this.subjectNameRegex = subjectNameRegex;
	},
	setSubjectFriendlyRegex: function (subjectFriendlyRegex) {
		this.subjectFriendlyRegex = subjectFriendlyRegex;
	},
	setSerialNumbersAllowed: function (serialNumbersAllowed) {
		this.serialNumbersAllowed = serialNumbersAllowed;
	},
	setKeyUsageRestrictions: function (keyUsageRestrictions) {
		this.keyUsageRestrictions = keyUsageRestrictions;
	},
	setSignatureElement: function (signatureElement) {
		this.signatureElement = signatureElement;
	},
	setUncheckedCheckboxIncluded: function(uncheckedCheckboxIncluded) {
		this.uncheckedCheckboxIncluded = uncheckedCheckboxIncluded;
	},
	setUncheckedRadioIncluded: function(uncheckedRadioIncluded) {
		this.uncheckedRadioIncluded = uncheckedRadioIncluded;
	},
	setUnselectedOptionIncluded: function(unselectedOptionIncluded) {
		this.unselectedOptionIncluded = unselectedOptionIncluded;
	},
	setExcludedElements: function(excludedElements) {
		this.excludedElements = excludedElements;
	},
	setIncludedElements: function(includedElements) {
		this.includedElements = includedElements;
	},
	setNonce: function(nonce) {
		this.nonce = nonce;
	},
	printAppletDeclaration: function (width, height) {
		if (BrowserDetect.browser == 'Explorer') {
			document.write('<object id="dsigApplet" classid="clsid:CAFEEFAC-0016-0000-FFFF-ABCDEFFEDCBA"');
			document.write('		codebase="' + this.protocol + '//java.sun.com/update/1.7.0/jinstall-7u55-windows-i586.cab"');
			document.write('        width="' + width + '" height="' + height + '">');
			document.write('	<param name="code" value="net.sf.dsig.DSApplet.class" />');
			document.write('	<param name="codebase_lookup" value="false" />');
			document.write('	<param name="archive" value="' + this.jarUrl + '" />');
			document.write('    <param name="userAgent" value="' + window.navigator.userAgent + '" />');
			document.write('	<param name="mayscript" value="true" />');
			for (var i in this) {
				if (typeof this[i] == 'string') {
					document.write('	<param name="' + i + '" value="' + this[i] + '" />');
				}
			}
			document.write('</object>');
		} else {
			document.write('<embed  id="dsigApplet" code="net.sf.dsig.DSApplet.class" archive="' + this.jarUrl + '"');
			document.write('        width="' + width + '" height="' + height + '"');
			document.write('		type="application/x-java-applet;version=1.7"');
			document.write('		codebase_lookup="false"');
			document.write('		pluginspage="http://java.com/en/download/index.jsp"');
			document.write('    	userAgent="' + window.navigator.userAgent + '"');
			document.write('		mayscript="true"');
			for (var i in this) {
				if (typeof this[i] == 'string') {
					document.write('		' + i + '="' + this[i] + '"');
				}
			}
			document.write('></embed>');
		}
	},
	fillAppletDeclaration: function (width, height, dsigId) {
		var innerHtml = '';
		if (BrowserDetect.browser == 'Explorer') {
			innerHtml += '<object id="dsigApplet" classid="clsid:CAFEEFAC-0016-0000-FFFF-ABCDEFFEDCBA"';
			innerHtml += '		  codebase="' + this.protocol + '//java.sun.com/update/1.7.0/jinstall-7u55-windows-i586.cab"';
			innerHtml += '        width="' + width + '" height="' + height + '">';
			innerHtml += '	<param name="code" value="net.sf.dsig.DSApplet.class" />';
			innerHtml += '	<param name="codebase_lookup" value="false" />';
			innerHtml += '	<param name="archive" value="' + this.jarUrl + '" />';
			innerHtml += '  <param name="userAgent" value="' + window.navigator.userAgent + '" />';
			innerHtml += '	<param name="mayscript" value="true" />';
			for (var i in this) {
				if (typeof this[i] == 'string') {
					innerHtml += '	<param name="' + i + '" value="' + this[i] + '" />';
				}
			}
			innerHtml += '</object>';
		} else {
			innerHtml += '<embed  id="dsigApplet" code="net.sf.dsig.DSApplet.class" archive="' + this.jarUrl + '"';
			innerHtml += '        width="' + width + '" height="' + height + '"';
			innerHtml += '		type="application/x-java-applet;version=1.7"';
			innerHtml += '		codebase_lookup="false"';
			innerHtml += '		pluginspage="http://java.com/en/download/index.jsp"';
			innerHtml += '    	userAgent="' + window.navigator.userAgent + '"';
			innerHtml += '		mayscript="true"';
			for (var i in this) {
				if (typeof this[i] == 'string') {
					innerHtml += '		' + i + '="' + this[i] + '"';
				}
			}
			innerHtml += '></embed>';
		}
		
		document.getElementById(dsigId).innerHTML = innerHtml;
	},
	signForm: function (form, alias) {
		return document.getElementById('dsigApplet').sign(form, alias);
	},
	signPlaintext: function (plaintext, alias) {
		return document.getElementById('dsigApplet').signPlaintext(plaintext, alias);
	},
	hasCertificates: function () {
		return document.getElementById('dsigApplet').hasCertificates();
	},
	getAliasedDescriptions: function() {
		return document.getElementById('dsigApplet').getAliasedDescriptions();
	}
};
