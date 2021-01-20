
//Script testing 14.2.1 control from OWASP ASVS 4.0:
//'Verify that all components are up to date, preferably using a dependency checker during build or compile time.'

//The script checks loops through all the alerts looking for alerts from RetireJS (pluginId 10003) and changes the title and description to match ASVS requirement 14.2.1
//For the script to work you need to install RetireJS add-on from the marketplace and use it with a spider on your website. Then run this script.


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
		if (alert.getPluginId() == 10003) {
            // update fields to mirror ASVS requirements
            alert.setRisk(0)
            alert.setConfidence(1)
            description = alert.getDescription()
            info = alert.getOtherInfo()
            alert.setDescription('Using older versions of software packages, for example jquery, may allow for exploitation of e.g. XSS on a website.  '+ description + ' Vulnerable to: \n' +info)
            alert.setName('14.2.1 Verify that all components are up to date, preferably using a dependency checker during build or compile time.')
            alert.setOtherInfo('Control failure')
            //https://www.javadoc.io/static/org.zaproxy/zap/2.9.0/org/zaproxy/zap/extension/alert/ExtensionAlert.html
            //https://groups.google.com/u/1/g/zaproxy-scripts/c/d7Aa1oW6RYA
            extAlert.updateAlert(alert)
          }
	}
}

