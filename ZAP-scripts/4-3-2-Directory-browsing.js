
//Script testing 4.3.2 control from OWASP ASVS 4.0:
//'Verify that directory browsing is disabled unless deliberately desired. Additionally, applications should not allow discovery or disclosure of file or directory metadata, such as Thumbs.db, .DS_Store, .git or .svn folders.'

extAlert = org.parosproxy.paros.control.Control.getSingleton().
    getExtensionLoader().getExtension(
        org.zaproxy.zap.extension.alert.ExtensionAlert.NAME) 


if (extAlert != null) {
//	var Alert = org.parosproxy.paros.core.scanner.Alert
	var alerts = extAlert.getAllAlerts()
     // cycle thorugh all alerts
	for (var i = 0; i < alerts.length; i++) {
		var alert = alerts[i]
          // choose only the ones whose pluginID matches RetireJS's plugin ID
		if (alert.getPluginId() == 10033) {
            // update fields to mirror ASVS requirements
            alert.setRisk(0)
            alert.setConfidence(1)
            description = alert.getDescription()
            alert.setDescription('A directory listing was found, which may reveals sensitive data.')
            alert.setName('4.3.2 Verify that directory browsing is disabled unless deliberately desired. Additionally, applications should not allow discovery or disclosure of file or directory metadata, such as Thumbs.db, .DS_Store, .git or .svn folders.')
            alert.setOtherInfo('Control failure, unless directory browsing was deliberately enabled.')
            //https://www.javadoc.io/static/org.zaproxy/zap/2.9.0/org/zaproxy/zap/extension/alert/ExtensionAlert.html
            //https://groups.google.com/u/1/g/zaproxy-scripts/c/d7Aa1oW6RYA
            extAlert.updateAlert(alert)
          }
	}
}

