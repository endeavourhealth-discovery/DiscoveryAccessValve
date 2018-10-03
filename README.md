# Discovery Access Valve
A Tomcat Catalina valve used to process the HttpServletRequest following 
successful Keycloak authentication and immediately after web.xml validation 
of the associated web application API layer. 

Used to validated the application app_name against the security context userId, i.e. the Keycloak userId.

##Deployment
The .jar file is deployed into the ${tomcat.home}/lib directory

The web application context.xml file is updated with the valve class reference 
after the KeycloakAuthenticatorValue reference, i.e: 

Valve className="org.endeavourhealth.DiscoveryAccessValve"

The web.xml file for the web application has an additional context-param added, for example:

    <context-param>
        <param-name>app_name</param-name>
        <param-value>User Manager</param-value>
    </context-param>


