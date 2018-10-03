package org.endeavourhealth;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.representations.AccessToken;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.Principal;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

public class DiscoveryAccessValve extends ValveBase {

    private static final Logger logger = Logger.getLogger(DiscoveryAccessValve.class.getName());

    /**
     * {@inheritDoc}
     */
    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        HttpServletRequest httpServletRequest = request.getRequest();

        //check for authenticated user
        Principal principal = httpServletRequest.getUserPrincipal();
        if (principal != null) {

            //basic servlet request info
            String userId = httpServletRequest.getUserPrincipal().getName();
            logger.log(Level.INFO, "Authenticated User ID: " + userId);

            String authHeader = httpServletRequest.getHeader("authorization");
            logger.log(Level.INFO, "Auth Header: {0}", authHeader);

            //keycloak access info
            KeycloakPrincipal kp = (KeycloakPrincipal)principal;
            AccessToken token = kp.getKeycloakSecurityContext().getToken();
            Set<String> realmRoles = token.getRealmAccess().getRoles();
            logger.log(Level.INFO, "Keyloak -> ID: "+token.getSubject());
            logger.log(Level.INFO, "Keyloak -> Name: "+token.getGivenName()+" "+token.getFamilyName());
            logger.log(Level.INFO, "Keyloak -> Roles: "+realmRoles);

            //validate application access against the app_name param from web.xml - call into user manager model interface
            String appId = httpServletRequest.getServletContext().getInitParameter("app_name");
            logger.log(Level.INFO, "app_name -> {0}", appId);

            boolean isUserAllowedAccess = appId.equalsIgnoreCase("User Manager");
            if (!isUserAllowedAccess) {

                logger.log(Level.INFO, "Application access not permitted -> send 403");
                response.sendError(403, "** Computer sez NO **");
                response.finishResponse();
            } else {

                //user allowed, continue valve pipeline
                getNext().invoke(request, response);
            }
        } else {

            //continue valve pipeline
            getNext().invoke(request, response);
        }
    }
}
