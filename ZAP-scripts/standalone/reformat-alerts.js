//Credit to BlazingWind on Github for thier implementation of this script https://github.com/BlazingWind/OWASP-ASVS-4.0-testing-guide

//Script testing the following controls from OWASP ASVS 4.0:
//5.3.4
//5.3.5
//5.3.10
//5.3.3
//5.3.7
//5.3.8
//5.1.2
//6.2.1
//5.3.9
//5.5.2
//14.2.1
//4.3.2


//The script checks loops through all the alerts looking for plugin ids that correspond to the ASVS controls 
//and changes the title and description to match the requirement

//alert plugin ids can be found here:
//https://www.zaproxy.org/docs/alerts/


extAlert = org.parosproxy.paros.control.Control.getSingleton().
    getExtensionLoader().getExtension(
        org.zaproxy.zap.extension.alert.ExtensionAlert.NAME) 


if (extAlert != null) {
//	var Alert = org.parosproxy.paros.core.scanner.Alert
	var alerts = extAlert.getAllAlerts()
     // cycle thorugh all alerts
	for (var i = 0; i < alerts.length; i++) {

		var alert = alerts[i]
          var id = alert.getPluginId(); // get plugin id for alert
          
          switch (id){ //set up cases for each id to change alert format to match ASVS
            case 40018: //sql injection
              description = alert.getDescription()
              alert.setName("5.3.4 & 5.3.5 Verify that where parameterized or safer mechanisms are not present, context-specific output encoding is used.");
              alert.setDescription("5.3.4 Verify that data selection or database queries (e.g. SQL, HQL, ORM, NoSQL) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from database injection attacks." + "\n" +"5.3.5 Verify that where parameterized or safer mechanisms are not present, context-specific output encoding is used to protect against injection attacks, such as the use of SQL escaping to protect against SQL injection." + "\n" + description)
              extAlert.updateAlert(alert);
              break;
            case 90029: //soap xml injection
              description = alert.getDescription()
              alert.setName("5.3.10 Verify that the application protects against XML injection attacks.");
              alert.setDescription('Verify that the application protects against XML injection attacks.' + "\n" + description)
              extAlert.updateAlert(alert);
              break;
            case 90021: //xpath injection
              description = alert.getDescription()
              alert.setName("5.3.10 Verify that the application protects against XPath injection attacks.");
              alert.setDescription('Verify that the application protects against XPath injection attacks.' + "\n" + description)
              extAlert.updateAlert(alert);
              break;
            case 40012: //reflected xss
              description = alert.getDescription()
              alert.setName("5.3.3 Verify that context-aware, preferably automated - or at worst, manual - output escaping protects against reflected XSS.");
              alert.setDescription('Verify that context-aware, preferably automated - or at worst, manual - output escaping protects against reflected XSS.' + "\n" + description)
              extAlert.updateAlert(alert);
              break;
            case 40014: //persistent xss
              description = alert.getDescription()
              alert.setName("5.3.3 Verify that context-aware, preferably automated - or at worst, manual - output escaping protects against stored XSS.");
              alert.setDescription('Verify that context-aware, preferably automated - or at worst, manual - output escaping protects against stored XSS.' + "\n" + description)
              extAlert.updateAlert(alert);
              break;
            case 40016: //persistent xss - prime
              description = alert.getDescription()
              alert.setName("5.3.3 Verify that context-aware, preferably automated - or at worst, manual - output escaping protects against stored XSS.");
              alert.setDescription('Verify that context-aware, preferably automated - or at worst, manual - output escaping protects against stored XSS.' + "\n" + description)
              extAlert.updateAlert(alert);
              break;
            case 40017: //persistent xss - spider
              description = alert.getDescription()
              alert.setName("5.3.3 Verify that context-aware, preferably automated - or at worst, manual - output escaping protects against stored XSS.");
              alert.setDescription('Verify that context-aware, preferably automated - or at worst, manual - output escaping protects against stored XSS.' + "\n" + description)
              extAlert.updateAlert(alert);
              break;
            case 40026: //dom based xss
              description = alert.getDescription()
              alert.setName("5.3.3 Verify that context-aware, preferably automated - or at worst, manual - output escaping protects against dom-based XSS.");
              alert.setDescription('Verify that context-aware, preferably automated - or at worst, manual - output escaping protects against dom-based XSS.' + "\n" + description)
              extAlert.updateAlert(alert);
              break;
            case 40015: //ldap injection
              description = alert.getDescription()
              alert.setName("5.3.7 Verify that the application protects against LDAP injection vulnerabilities.");
              alert.setDescription('Verify that the application protects against LDAP injection vulnerabilities, or that specific security controls to prevent LDAP injection have been implemented.' + "\n" + description)
              extAlert.updateAlert(alert);
              break;
            case 90020: //remote os command injection
              description = alert.getDescription()
              alert.setName("5.3.8 Verify that the application protects against OS command injection.");
              alert.setDescription('Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding.' + "\n" + description)
              extAlert.updateAlert(alert);
              break;
            case 20014: //parameter pollution
              description = alert.getDescription()
              alert.setName("5.1.2 Verify that frameworks protect against mass parameter assignment attacks.");
              alert.setDescription('Verify that frameworks protect against mass parameter assignment attacks, or that the application has countermeasures to protect against unsafe parameter assignment, such as marking fields private or similar.' + "\n" + description)
              extAlert.updateAlert(alert);
              break;
            case 90024: //generic padding oracle attack
              description = alert.getDescription()
              alert.setName("6.2.1 Verify that all cryptographic modules fail securely, and errors are handled in a way that does not enable Padding Oracle attacks.");
              alert.setDescription('Verify that all cryptographic modules fail securely, and errors are handled in a way that does not enable Padding Oracle attacks.' + "\n" + description)
              extAlert.updateAlert(alert);
              break;
            case 4: //rfi
              description = alert.getDescription()
              alert.setName("5.3.9 & 13.1.1 Verify that the application protects against Local File Inclusion (LFI) or Remote File Inclusion (RFI) attacks.");
              alert.setDescription("5.3.9 Verify that the application protects against Local File Inclusion (LFI) or Remote File Inclusion (RFI) attacks." + "\n" + "13.1.1 Verify that all application components use the same encodings and parsers to avoid parsing attacks that exploit different URI or file parsing behavior that could be used in SSRF and RFI attacks." + "\n" + description)
              extAlert.updateAlert(alert);
              break;
            case 90023: //xml external entity attack
              description = alert.getDescription()
              alert.setName("5.5.2 Verify that the application correctly restricts XML parsers.");
              alert.setDescription('Verify that the application correctly restricts XML parsers to only use the most restrictive configuration possible and to ensure that unsafe features such as resolving external entities are disabled to prevent XML eXternal Entity (XXE) attacks.' + "\n" + description)
              extAlert.updateAlert(alert);
              break;
            case 10003: //up to date components
              description = alert.getDescription()
              info = alert.getOtherInfo()
              alert.setDescription('Using older versions of software packages, for example jquery, may allow for exploitation of e.g. XSS on a website.  '+ description + ' Vulnerable to: \n' +info)
              alert.setName('14.2.1 Verify that all components are up to date, preferably using a dependency checker during build or compile time.')
              extAlert.updateAlert(alert);
              break;
            case 0: //directory browsing
              description = alert.getDescription()
              alert.setDescription('A directory listing was found, which may reveals sensitive data.')
              alert.setName('4.3.2 Verify that directory browsing is disabled unless deliberately desired. Additionally, applications should not allow discovery or disclosure of file or directory metadata, such as Thumbs.db, .DS_Store, .git or .svn folders.')
              extAlert.updateAlert(alert);
              break;
            default:
              break;
          }
	}
}