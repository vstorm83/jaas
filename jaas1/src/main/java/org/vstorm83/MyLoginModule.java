/*
 * Copyright (C) 2013 eXo Platform SAS.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.vstorm83;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import java.security.Principal;
import java.util.Map;
import java.util.Set;

import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.callback.UsernamePasswordHandler;

/**
 * @author <a href="mailto:phuong.vu@exoplatform.com">Vu Viet Phuong</a>
 * @version $Id$
 *
 */
public class MyLoginModule implements LoginModule{

    protected Subject subject;

    protected CallbackHandler callbackHandler;

    @SuppressWarnings("unchecked")
    protected Map sharedState;

    @SuppressWarnings("unchecked")
    protected Map options;
    
    /**
     * @see javax.security.auth.spi.LoginModule#initialize(javax.security.auth.Subject, javax.security.auth.callback.CallbackHandler, java.util.Map, java.util.Map)
     */
    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
        this.subject = subject;
        this.callbackHandler = callbackHandler;
        this.sharedState = sharedState;
        this.options = options;
    }

    /**
     * @see javax.security.auth.spi.LoginModule#login()
     */
    @Override
    public boolean login() throws LoginException {
        System.out.println("login");
         try
         {
              Callback[] callbacks = new Callback[2];
              callbacks[0] = new NameCallback("Username");
              callbacks[1] = new PasswordCallback("Password", false);

              callbackHandler.handle(callbacks);
              final String username = ((NameCallback)callbacks[0]).getName();
              String password = new String(((PasswordCallback)callbacks[1]).getPassword());
              ((PasswordCallback)callbacks[1]).clearPassword();
              if (username == null || password == null)
                 return false;
              else if (username.equals("root") && password.equals("gtn")) {
                  sharedState.put("javax.security.auth.login.name", username);
                  subject.getPrivateCredentials().add(password);
                  subject.getPublicCredentials().add(username);
                  
//                  SimpleGroup grp = new SimpleGroup("users");
//                  SimplePrincipal usr = new SimplePrincipal(username); 
//                  grp.addMember(usr);
//                  subject.getPrincipals().add(grp);
//                  subject.getPrincipals().add(usr);
                  return true;                  
              } 
              return false;
         }
         catch (final Exception e)
         {
            throw new LoginException(e.getMessage());
         }
    }

    @Override
    public boolean commit() throws LoginException {
        Set<Principal> principals = subject.getPrincipals();
System.out.println("Commiting");
        SimpleGroup grp = new SimpleGroup("Roles");
        grp.addMember(new SimpleGroup("users"));
        SimplePrincipal usr = new SimplePrincipal("root"); 
        principals.add(usr);
        
        grp.addMember(usr);
        principals.add(grp);
        return true;
    }

    @Override
    public boolean abort() throws LoginException {
        return true;
    }

    @Override
    public boolean logout() throws LoginException {
        return true;
    }

}
