# Discovery Access Valve

A Tomcat Catalina valve used to process the HttpServletRequest following 
successful Keycloak authentication and immediately after web.xml validation 
of the associated web application API layer. Used to validated the application 
app_name against the security context userId, i.e. the Keycloak userId.

The .jar file is deployed into the ${tomcat.home}/lib directory

The web application context.xml file is updated with the valve class reference, i.e: 

Valve className="org.endeavourhealth.DiscoveryAccessValve"


