/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.swang.keycloak;

import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.*;
import org.keycloak.models.utils.SystemClientUtil;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

import javax.ws.rs.GET;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;
import java.net.URI;


public class TokenAuthnResourceProvider implements RealmResourceProvider {

    private KeycloakSession session;

    public TokenAuthnResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @GET
    public Response authenticate(@QueryParam("token") String token, @QueryParam("redirectUrl") String redirectUrl) {
        System.out.println("token:"+token);
        //try to get user info from portal...
        //get email of user from remote

        ClientConnection clientConnection = session.getContext().getConnection();
        RealmModel realm = session.getContext().getRealm();
        EventBuilder event = new EventBuilder(realm, session, clientConnection);

        ClientModel client = SystemClientUtil.getSystemClient(realm);
        RootAuthenticationSessionModel rootAuthSession = new AuthenticationSessionManager(session).createAuthenticationSession(realm, true);
        AuthenticationSessionModel authenticationSession = rootAuthSession.createAuthenticationSession(client);
        //bob is a user in the realm
        UserModel userModel = session.users().getUserByUsername("bob", realm);
        authenticationSession.setAuthenticatedUser(userModel);

        ClientSessionContext clientSessionContext = AuthenticationProcessor.attachSession(authenticationSession, null, session, realm, clientConnection, event);
        UserSessionModel userSession = clientSessionContext.getClientSession().getUserSession();

        AuthenticationManager.createLoginCookie(session,realm,userModel,userSession,session.getContext().getUri(),clientConnection);

        return  Response.status(302).location(URI.create(redirectUrl)).build();
    }

    @Override
    public void close() {
    }

}
