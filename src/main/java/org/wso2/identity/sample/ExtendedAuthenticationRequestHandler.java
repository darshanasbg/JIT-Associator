/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.identity.sample;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.impl.DefaultAuthenticationRequestHandler;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;


public class ExtendedAuthenticationRequestHandler extends DefaultAuthenticationRequestHandler {


    private static final Log log = LogFactory.getLog(ExtendedAuthenticationRequestHandler.class);
    private static volatile ExtendedAuthenticationRequestHandler instance;

    public static ExtendedAuthenticationRequestHandler getInstance() {

        if (instance == null) {
            synchronized (ExtendedAuthenticationRequestHandler.class) {
                if (instance == null) {
                    instance = new ExtendedAuthenticationRequestHandler();
                }
            }
        }

        return instance;
    }

    /**
     * Executes the authentication flow
     *
     * @param request
     * @param response
     * @throws FrameworkException
     */
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AuthenticationContext context) throws FrameworkException {

        if (log.isDebugEnabled()) {
            log.debug("In authentication flow");
        }

        if (context.isReturning()) {
            // if "Deny" or "Cancel" pressed on the login page.
            if (request.getParameter(FrameworkConstants.RequestParams.DENY) != null) {
                handleDenyFromLoginPage(request, response, context);
                return;
            }

            // handle remember-me option from the login page
            handleRememberMeOptionFromLoginPage(request, context);
        }

        int currentStep = context.getCurrentStep();

        // if this is the start of the authentication flow
        if (currentStep == 0) {
            handleSequenceStart(request, response, context);
        }

        SequenceConfig seqConfig = context.getSequenceConfig();
        List<AuthenticatorConfig> reqPathAuthenticators = seqConfig.getReqPathAuthenticators();

        // if SP has request path authenticators configured and this is start of
        // the flow
        if (reqPathAuthenticators != null && !reqPathAuthenticators.isEmpty() && currentStep == 0) {
            // call request path sequence handler
            FrameworkUtils.getRequestPathBasedSequenceHandler().handle(request, response, context);
        }

        // if no request path authenticators or handler returned cannot handle
        if (!context.getSequenceConfig().isCompleted()
                || (reqPathAuthenticators == null || reqPathAuthenticators.isEmpty())) {
            // call step based sequence handler
            FrameworkUtils.getStepBasedSequenceHandler().handle(request, response, context);
        }

        Object enrichmentTriggered = context.getProperty(Constants.ENRICHMENT_TRIGGERED);
        boolean enrichmentTriggredBool = false;
        if (enrichmentTriggered != null) {
            enrichmentTriggredBool = (Boolean) enrichmentTriggered;
        }

        if (context.getSequenceConfig().isCompleted() && !isPostAuthenticationExtensionCompleted(context) && !enrichmentTriggredBool) {
            // call post authentication handler
            FrameworkUtils.getPostAuthenticationHandler().handle(request, response, context);
        }

        // if flow completed, send response back
        if (isPostAuthenticationExtensionCompleted(context)) {
            concludeFlow(request, response, context);
        } else { // redirecting outside
            FrameworkUtils.addAuthenticationContextToCache(context.getContextIdentifier(), context);
        }
    }

    private void handleDenyFromLoginPage(HttpServletRequest request, HttpServletResponse response,
                                         AuthenticationContext context) throws FrameworkException {
        if (log.isDebugEnabled()) {
            log.debug("User has pressed Deny or Cancel in the login page. Terminating the authentication flow");
        }

        context.getSequenceConfig().setCompleted(true);
        context.setRequestAuthenticated(false);
        //No need to handle authorization, because the authentication is not completed
        concludeFlow(request, response, context);
    }

    private void handleRememberMeOptionFromLoginPage(HttpServletRequest request, AuthenticationContext context) {
        String rememberMe = request.getParameter("chkRemember");

        if (rememberMe != null && "on".equalsIgnoreCase(rememberMe)) {
            context.setRememberMe(true);
        } else {
            context.setRememberMe(false);
        }
    }

}
