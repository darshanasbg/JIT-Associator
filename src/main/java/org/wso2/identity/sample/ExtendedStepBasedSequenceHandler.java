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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.utils.URIBuilder;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.handler.sequence.impl.DefaultStepBasedSequenceHandler;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.user.profile.mgt.UserProfileAdmin;
import org.wso2.carbon.identity.user.profile.mgt.UserProfileException;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.identity.sample.internal.JITAccountAssociatorServiceComponent;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Calls for JIT Provisioning before checks for user associations
 */
public class ExtendedStepBasedSequenceHandler extends DefaultStepBasedSequenceHandler {

    private static final Log log = LogFactory.getLog(ExtendedStepBasedSequenceHandler.class);

    /**
     * Executes the steps
     *
     * @param request
     * @param response
     * @throws FrameworkException
     * @throws FrameworkException
     */
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AuthenticationContext context) throws FrameworkException {

        if (log.isDebugEnabled()) {
            log.debug("Executing the Step Based Authentication...");
        }

        boolean isEnrichmentBasedProvisioningFlow = false;
        String username = "";

        while (!context.getSequenceConfig().isCompleted()) {

            int currentStep = context.getCurrentStep();

            // let's initialize the step count to 1 if this the beginning of the sequence
            if (currentStep == 0) {
                currentStep++;
                context.setCurrentStep(currentStep);
            }

            StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(currentStep);
            // if the current step is completed
            if (stepConfig != null && stepConfig.isCompleted()) {
                stepConfig.setCompleted(false);
                stepConfig.setRetrying(false);

                // if the request didn't fail during the step execution
                if (context.isRequestAuthenticated()) {
                    if (log.isDebugEnabled()) {
                        log.debug("Step " + stepConfig.getOrder()
                                + " is completed. Going to get the next one.");
                    }

                    currentStep = context.getCurrentStep() + 1;
                    context.setCurrentStep(currentStep);
                    stepConfig = context.getSequenceConfig().getStepMap().get(currentStep);

                } else {

                    if (log.isDebugEnabled()) {
                        log.debug("Authentication has failed in the Step "
                                + (context.getCurrentStep()));
                    }

                    // if the step contains multiple login options, we should give the user to retry
                    // authentication
                    if (stepConfig.isMultiOption() && !context.isPassiveAuthenticate()) {
                        stepConfig.setRetrying(true);
                        context.setRequestAuthenticated(true);
                    } else {
                        context.getSequenceConfig().setCompleted(true);
                        resetAuthenticationContext(context);
                        continue;
                    }
                }

                resetAuthenticationContext(context);
            }

            // if no further steps exists
            if (stepConfig == null) {

                if (log.isDebugEnabled()) {
                    log.debug("There are no more steps to execute");
                }

                // if no step failed at authentication we should do post authentication work (e.g.
                // claim handling, provision etc)
                if (context.isRequestAuthenticated()) {

                    if (log.isDebugEnabled()) {
                        log.debug("Request is successfully authenticated");
                    }

                    Map<String, String> localClaimValues = null;
                    List<String> locallyMappedUserRoles = null;

//                    String originalExternalIdpSubjectValueForThisStep =
//                            stepConfig.getAuthenticatedUser().getAuthenticatedSubjectIdentifier();

                    context.getSequenceConfig().setCompleted(true);
                    if (Constants.IS_ENRICHMENT_TRIGGERED_ENABLED) {
                        boolean isUserExist = false;
                        boolean fedarationFlow = false;
                        boolean isJitProvisioningEnabled = false;
                        SequenceConfig sequenceConfig = context.getSequenceConfig();
                        for (Map.Entry<Integer, StepConfig> entry : sequenceConfig.getStepMap().entrySet()) {
                            StepConfig config = entry.getValue();
                            AuthenticatorConfig authenticatorConfig = config.getAuthenticatedAutenticator();
                            ApplicationAuthenticator authenticator = authenticatorConfig
                                    .getApplicationAuthenticator();
                            if (authenticator instanceof FederatedApplicationAuthenticator) {
                                fedarationFlow = true;
                                ExternalIdPConfig externalIdPConfig = null;
                                try {
                                    externalIdPConfig = ConfigurationFacade.getInstance()
                                            .getIdPConfigByName(config.getAuthenticatedIdP(),
                                                    context.getTenantDomain());
                                    context.setExternalIdP(externalIdPConfig);
                                } catch (IdentityProviderManagementException e) {
                                    new FrameworkException("Error while checking user existence", e);
                                }
                                Map<ClaimMapping, String> extAttrs;
                                Map<String, String> extAttibutesValueMap;
                                Map<String, String> idpClaimValues = null;

                                Map<String, String> mappedAttrs = new HashMap<>();
                                isJitProvisioningEnabled = externalIdPConfig.isProvisioningEnabled();
                                extAttrs = config.getAuthenticatedUser().getUserAttributes();
                                extAttibutesValueMap = FrameworkUtils.getClaimMappings(extAttrs, false);

                                if (config.isSubjectIdentifierStep()) {
                                    username = config.getAuthenticatedUser().getAuthenticatedSubjectIdentifier();
                                    try {
                                        String provisioningUserStoreId = externalIdPConfig.getProvisioningUserStoreId();
                                        RealmService realmService = JITAccountAssociatorServiceComponent.getRealmService();
                                        UserRealm realm = (UserRealm) realmService.getTenantUserRealm(IdentityTenantUtil.getTenantId(context.getTenantDomain()));
                                        String userStoreDomain = getUserStoreDomain(provisioningUserStoreId, realm);
                                        UserStoreManager userStoreManager = getUserStoreManager(realm, userStoreDomain);
                                        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
                                        isUserExist = userStoreManager.isExistingUser(tenantAwareUsername);
                                        if (isUserExist) {
                                            break;
                                        }
                                    } catch (UserStoreException e) {
                                        new FrameworkException("Error while checking user existence", e);
                                    }
                                }
                                if(config.isSubjectAttributeStep()) {
                                    if (config.isSubjectAttributeStep()) {
                                        String idpRoleClaimUri = getIdpRoleClaimUri(externalIdPConfig);

                                        locallyMappedUserRoles = getLocallyMappedUserRoles(sequenceConfig,
                                                externalIdPConfig, extAttibutesValueMap, idpRoleClaimUri);

                                        if (idpRoleClaimUri != null && getServiceProviderMappedUserRoles(sequenceConfig,
                                                locallyMappedUserRoles) != null) {
                                            extAttibutesValueMap.put(idpRoleClaimUri, getServiceProviderMappedUserRoles(sequenceConfig,
                                                    locallyMappedUserRoles));
                                        }

                                        if (mappedAttrs == null || mappedAttrs.isEmpty()) {
                                            // do claim handling
                                            handleClaimMappings(config, context,
                                                    extAttibutesValueMap, true);
                                            // external claim values mapped to local claim uris.
                                            localClaimValues = (Map<String, String>) context
                                                    .getProperty(FrameworkConstants.UNFILTERED_LOCAL_CLAIM_VALUES);

                                        }

                                    }
                                }
                            }
                        }

                        String missingClaims = getMissingClaims(username, context, locallyMappedUserRoles,localClaimValues);

                        if (!isUserExist && fedarationFlow && isJitProvisioningEnabled && StringUtils.isNotBlank(missingClaims)) {
                            try {
                                if (log.isDebugEnabled()) {
                                    log.debug("Mandatory claims missing for the application : " + missingClaims);
                                }
                                URIBuilder uriBuilder = new URIBuilder("/authenticationendpoint/claims.do");
                                uriBuilder.addParameter(FrameworkConstants.MISSING_CLAIMS,
                                        missingClaims);
                                uriBuilder.addParameter(FrameworkConstants.SESSION_DATA_KEY,
                                        context.getContextIdentifier());
                                uriBuilder.addParameter("spName",
                                        context.getSequenceConfig().getApplicationConfig().getApplicationName());
                                uriBuilder.addParameter("spTenantDomain",
                                        context.getTenantDomain());
                                response.sendRedirect(uriBuilder.build().toString());
                                if (log.isDebugEnabled()) {
                                    log.debug("Redirecting to outside to enrich claims");
                                }
                                isEnrichmentBasedProvisioningFlow = true;
                                context.setProperty(Constants.ENRICHMENT_TRIGGERED, true);
                                continue;
                            } catch (IOException e) {
                                throw new FrameworkException("Error while redirecting to request claims", e);
                            } catch (URISyntaxException e) {
                                throw new FrameworkException("Error while building redirect URI", e);
                            }
                        }
                    }
                    handlePostAuthentication(request, response, context);

                }

                // we should get out of steps now.
                if (log.isDebugEnabled()) {
                    log.debug("Step processing is completed");
                }
                continue;
            }

            // if the sequence is not completed, we have work to do.
            if (log.isDebugEnabled()) {
                log.debug("Starting Step: " + stepConfig.getOrder());
            }

            FrameworkUtils.getStepHandler().handle(request, response, context);

            // if step is not completed, that means step wants to redirect to outside
            if (!stepConfig.isCompleted()) {
                if (log.isDebugEnabled()) {
                    log.debug("Step is not complete yet. Redirecting to outside.");
                }
                return;
            }

            context.setReturning(false);
        }

        Object enrichmentTriggered = context.getProperty(Constants.ENRICHMENT_TRIGGERED);
        boolean enrichmentTriggredBool = false;
        if (enrichmentTriggered != null) {
            enrichmentTriggredBool = (Boolean) enrichmentTriggered;
        }

        if (enrichmentTriggredBool && !isEnrichmentBasedProvisioningFlow) {
            handlePostAuthentication(request, response, context);
            context.setProperty(Constants.ENRICHMENT_TRIGGERED, false);
        }
    }



    @SuppressWarnings("unchecked")
    protected void handlePostAuthentication(HttpServletRequest request,
                                            HttpServletResponse response, AuthenticationContext context)
            throws FrameworkException {

        if (log.isDebugEnabled()) {
            log.debug("Handling Post Authentication tasks");
        }



        Object enrichmentTriggered = context.getProperty(Constants.ENRICHMENT_TRIGGERED);
        boolean enrichmentTriggredBool = false;
        if (enrichmentTriggered != null) {
            enrichmentTriggredBool = (Boolean) enrichmentTriggered;
        }

        Map<String, String> enrichedClaims = new HashMap<String, String>();
        if (enrichmentTriggredBool) {

            Map<String, String[]> requestParams = request.getParameterMap();
            for (String key : requestParams.keySet()) {
                if (key.startsWith(FrameworkConstants.RequestParams.MANDOTARY_CLAIM_PREFIX)) {

                    String localClaimURI = key.substring(FrameworkConstants.RequestParams.MANDOTARY_CLAIM_PREFIX.length());
                    enrichedClaims.put(localClaimURI, requestParams.get(key)[0]);
                }
            }
        }

        SequenceConfig sequenceConfig = context.getSequenceConfig();
        StringBuilder jsonBuilder = new StringBuilder();

        boolean subjectFoundInStep = false;
        boolean subjectAttributesFoundInStep = false;
        int stepCount = 1;
        Map<String, String> mappedAttrs = new HashMap<>();
        Map<ClaimMapping, String> authenticatedUserAttributes = new HashMap<>();

        for (Map.Entry<Integer, StepConfig> entry : sequenceConfig.getStepMap().entrySet()) {
            StepConfig stepConfig = entry.getValue();
            AuthenticatorConfig authenticatorConfig = stepConfig.getAuthenticatedAutenticator();
            ApplicationAuthenticator authenticator = authenticatorConfig
                    .getApplicationAuthenticator();

            // build the authenticated idps JWT to send to the calling servlet.
            if (stepCount == 1) {
                jsonBuilder.append("\"idps\":");
                jsonBuilder.append("[");
            }

            // build the JSON object for this step
            jsonBuilder.append("{");
            jsonBuilder.append("\"idp\":\"").append(stepConfig.getAuthenticatedIdP()).append("\",");
            jsonBuilder.append("\"authenticator\":\"").append(authenticator.getName()).append("\"");

            if (stepCount != sequenceConfig.getStepMap().size()) {
                jsonBuilder.append("},");
            } else {
                // wrap up the JSON object
                jsonBuilder.append("}");
                jsonBuilder.append("]");

                sequenceConfig.setAuthenticatedIdPs(IdentityApplicationManagementUtil.getSignedJWT(
                        jsonBuilder.toString(), sequenceConfig.getApplicationConfig()
                                .getServiceProvider()));

                stepConfig.setSubjectIdentifierStep(!subjectFoundInStep);

                stepConfig.setSubjectAttributeStep(!subjectAttributesFoundInStep);
            }

            stepCount++;

            if (authenticator instanceof FederatedApplicationAuthenticator) {

                ExternalIdPConfig externalIdPConfig = null;
                try {
                    externalIdPConfig = ConfigurationFacade.getInstance()
                            .getIdPConfigByName(stepConfig.getAuthenticatedIdP(),
                                    context.getTenantDomain());
                } catch (IdentityProviderManagementException e) {
                    log.error("Exception while getting IdP by name", e);
                }

                context.setExternalIdP(externalIdPConfig);

                String originalExternalIdpSubjectValueForThisStep =
                        stepConfig.getAuthenticatedUser().getAuthenticatedSubjectIdentifier();

                if (externalIdPConfig == null) {
                    String errorMsg = "An External IdP cannot be null for a FederatedApplicationAuthenticator";
                    log.error(errorMsg);
                    throw new FrameworkException(errorMsg);
                }

                Map<ClaimMapping, String> extAttrs;
                Map<String, String> extAttibutesValueMap;
                Map<String, String> localClaimValues = null;
                Map<String, String> idpClaimValues = null;
                List<String> locallyMappedUserRoles = null;

                extAttrs = stepConfig.getAuthenticatedUser().getUserAttributes();
                extAttibutesValueMap = FrameworkUtils.getClaimMappings(extAttrs, false);

                if (stepConfig.isSubjectAttributeStep()) {

                    subjectAttributesFoundInStep = true;

                    String idpRoleClaimUri = getIdpRoleClaimUri(externalIdPConfig);

                    locallyMappedUserRoles = getLocallyMappedUserRoles(sequenceConfig,
                            externalIdPConfig, extAttibutesValueMap, idpRoleClaimUri);

                    if (idpRoleClaimUri != null && getServiceProviderMappedUserRoles(sequenceConfig,
                            locallyMappedUserRoles) != null) {
                        extAttibutesValueMap.put(idpRoleClaimUri, getServiceProviderMappedUserRoles(sequenceConfig,
                                locallyMappedUserRoles));
                    }

                    if (mappedAttrs == null || mappedAttrs.isEmpty()) {
                        // do claim handling


                        // Original
                        // { (http://foursquare/username, darshana), (http://foursquare/email, darshana@wso2.com)}
                        mappedAttrs = handleClaimMappings(stepConfig, context,
                                extAttibutesValueMap, true);
                        // But here it converted as following
                        // { (name, darshana), (mail, darshana@wso2.com)}


                        // external claim values mapped to local claim uris.
                        localClaimValues = (Map<String, String>) context
                                .getProperty(FrameworkConstants.UNFILTERED_LOCAL_CLAIM_VALUES);

                        idpClaimValues = (Map<String, String>) context
                                .getProperty(FrameworkConstants.UNFILTERED_IDP_CLAIM_VALUES);
                    }

                }

                // do user provisioning. we should provision the user with the original external
                // subject identifier.
                if (externalIdPConfig.isProvisioningEnabled()) {

                    if (localClaimValues == null) {
                        localClaimValues = new HashMap<>();
                    }
                    localClaimValues.put(Constants.ASSOCIATED_ID, originalExternalIdpSubjectValueForThisStep);
                    localClaimValues.put(Constants.IDP_ID, stepConfig.getAuthenticatedIdP());
                    localClaimValues.putAll(enrichedClaims);
                    handleJitProvisioning(originalExternalIdpSubjectValueForThisStep, context,
                            locallyMappedUserRoles, localClaimValues);
                    //{ (name, darshana), (mail, darshana@wso2.com)}
                }

                if (stepConfig.isSubjectIdentifierStep()) {
                    // there can be only step for subject attributes.

                    subjectFoundInStep = true;
                    String associatedID = null;

                    // now we know the value of the subject - from the external identity provider.

                    if (sequenceConfig.getApplicationConfig().isAlwaysSendMappedLocalSubjectId()) {

                        // okay - now we need to find out the corresponding mapped local subject
                        // identifier.

                        UserProfileAdmin userProfileAdmin = UserProfileAdmin.getInstance();
                        try {
                            // start tenant flow
                            FrameworkUtils.startTenantFlow(context.getTenantDomain());
                            associatedID = userProfileAdmin.getNameAssociatedWith(stepConfig.getAuthenticatedIdP(),
                                    originalExternalIdpSubjectValueForThisStep);
                            if (StringUtils.isNotBlank(associatedID)) {
                                if (log.isDebugEnabled()) {
                                    log.debug("User " + stepConfig.getAuthenticatedUser() +
                                            " has an associated account as " + associatedID + ". Hence continuing as " +
                                            associatedID);
                                }
                                stepConfig.getAuthenticatedUser().setUserName(associatedID);
                                stepConfig.getAuthenticatedUser().setTenantDomain(context.getTenantDomain());
                                stepConfig.setAuthenticatedUser(stepConfig.getAuthenticatedUser());
                            } else {
                                if (log.isDebugEnabled()) {
                                    log.debug("User " + stepConfig.getAuthenticatedUser() +
                                            " doesn't have an associated" +
                                            " account. Hence continuing as the same user.");
                                }
                            }
                        } catch (UserProfileException e) {
                            throw new FrameworkException("Error while getting associated local user ID for "
                                    + originalExternalIdpSubjectValueForThisStep, e);
                        } finally {
                            // end tenant flow
                            FrameworkUtils.endTenantFlow();
                        }
                    }


                    if (associatedID != null && associatedID.trim().length() > 0) {

                        handleClaimMappings(stepConfig, context, extAttibutesValueMap, true);
                        localClaimValues = (Map<String, String>) context
                                .getProperty(FrameworkConstants.UNFILTERED_LOCAL_CLAIM_VALUES);

                        idpClaimValues = (Map<String, String>) context
                                .getProperty(FrameworkConstants.UNFILTERED_IDP_CLAIM_VALUES);
                        // we found an associated user identifier
                        // build the full qualified user id for the associated user
                        String fullQualifiedAssociatedUserId = FrameworkUtils.prependUserStoreDomainToName(
                                associatedID + UserCoreConstants.TENANT_DOMAIN_COMBINER + context.getTenantDomain());
                        sequenceConfig.setAuthenticatedUser(AuthenticatedUser
                                .createLocalAuthenticatedUserFromSubjectIdentifier(
                                        fullQualifiedAssociatedUserId));

                        sequenceConfig.getApplicationConfig().setMappedSubjectIDSelected(true);

                        // if we found a local mapped user - then we will also take attributes from
                        // that user - this will load local claim values for the user.
                        mappedAttrs = handleClaimMappings(stepConfig, context, null, false);

                        // if no requested claims are selected, send all local mapped claim values or idp claim values
                        if (context.getSequenceConfig().getApplicationConfig().getRequestedClaimMappings() == null ||
                                context.getSequenceConfig().getApplicationConfig().getRequestedClaimMappings()
                                        .isEmpty()) {

                            if (localClaimValues != null && !localClaimValues.isEmpty()) {
                                mappedAttrs = localClaimValues;
                            } else if (idpClaimValues != null && !idpClaimValues.isEmpty()) {
                                mappedAttrs = idpClaimValues;
                            }
                        }

                        authenticatedUserAttributes = FrameworkUtils.buildClaimMappings(mappedAttrs);

                        // in this case associatedID is a local user name - belongs to a tenant in IS.
                        String tenantDomain = MultitenantUtils.getTenantDomain(associatedID);
                        Map<String, Object> authProperties = context.getProperties();

                        if (authProperties == null) {
                            authProperties = new HashMap<>();
                            context.setProperties(authProperties);
                        }

                        authProperties.put(USER_TENANT_DOMAIN, tenantDomain);

                        if (log.isDebugEnabled()) {
                            log.debug("Authenticated User: " +
                                    sequenceConfig.getAuthenticatedUser().getAuthenticatedSubjectIdentifier());
                            log.debug("Authenticated User Tenant Domain: " + tenantDomain);
                        }

                    } else {

                        sequenceConfig.setAuthenticatedUser(new AuthenticatedUser(stepConfig.getAuthenticatedUser()));

                        // Only place we do not set the setAuthenticatedUserTenantDomain into the sequenceConfig

                    }

                }

                if(stepConfig.isSubjectAttributeStep()) {
                    if (!sequenceConfig.getApplicationConfig().isMappedSubjectIDSelected()) {
                        // if we found the mapped subject - then we do not need to worry about
                        // finding attributes.

                        // if no requested claims are selected, send all local mapped claim values or idp claim values
                        if (context.getSequenceConfig().getApplicationConfig().getRequestedClaimMappings() == null ||
                                context.getSequenceConfig().getApplicationConfig().getRequestedClaimMappings().isEmpty()) {

                            if (localClaimValues != null && !localClaimValues.isEmpty()) {
                                mappedAttrs = localClaimValues;
                            } else if (idpClaimValues != null && !idpClaimValues.isEmpty()) {
                                mappedAttrs = idpClaimValues;
                            }
                        }
                        authenticatedUserAttributes = FrameworkUtils.buildClaimMappings(mappedAttrs);
                    }
                }
            } else {

                if (stepConfig.isSubjectIdentifierStep()) {
                    subjectFoundInStep = true;
                    sequenceConfig.setAuthenticatedUser(new AuthenticatedUser(stepConfig.getAuthenticatedUser()));

                    if (log.isDebugEnabled()) {
                        log.debug("Authenticated User: " + sequenceConfig.getAuthenticatedUser().getUserName());
                        log.debug("Authenticated User Tenant Domain: " + sequenceConfig.getAuthenticatedUser()
                                .getTenantDomain());
                    }
                }

                if (stepConfig.isSubjectAttributeStep()) {
                    subjectAttributesFoundInStep = true;
                    // local authentications
                    mappedAttrs = handleClaimMappings(stepConfig, context, null, false);

                    String spRoleUri = getSpRoleClaimUri(sequenceConfig.getApplicationConfig());

                    String roleAttr = mappedAttrs.get(spRoleUri);

                    if (StringUtils.isNotBlank(roleAttr)) {

                        String[] roles = roleAttr.split(",");
                        mappedAttrs.put(
                                spRoleUri,
                                getServiceProviderMappedUserRoles(sequenceConfig,
                                        Arrays.asList(roles)));
                    }

                    authenticatedUserAttributes = FrameworkUtils.buildClaimMappings(mappedAttrs);
                }
            }
        }

        String subjectClaimURI = sequenceConfig.getApplicationConfig().getSubjectClaimUri();
        String subjectValue = (String) context.getProperty("ServiceProviderSubjectClaimValue");
        if (StringUtils.isNotBlank(subjectClaimURI)) {
            if (subjectValue != null) {
                sequenceConfig.getAuthenticatedUser().setAuthenticatedSubjectIdentifier(subjectValue);

                if (log.isDebugEnabled()) {
                    log.debug("Authenticated User: " +
                            sequenceConfig.getAuthenticatedUser().getAuthenticatedSubjectIdentifier());
                    log.debug("Authenticated User Tenant Domain: " + sequenceConfig.getAuthenticatedUser()
                            .getTenantDomain());
                }
            } else {
                log.warn("Subject claim could not be found. Defaulting to Name Identifier.");
                if (StringUtils.isNotBlank(sequenceConfig.getAuthenticatedUser().getUserName())) {
                    sequenceConfig.getAuthenticatedUser().setAuthenticatedSubjectIdentifier(sequenceConfig
                            .getAuthenticatedUser().getUsernameAsSubjectIdentifier(sequenceConfig.getApplicationConfig()
                                    .isUseUserstoreDomainInLocalSubjectIdentifier(), sequenceConfig
                                    .getApplicationConfig().isUseTenantDomainInLocalSubjectIdentifier()));
                }
            }

        } else {
            if (StringUtils.isNotBlank(sequenceConfig.getAuthenticatedUser().getUserName())) {
                sequenceConfig.getAuthenticatedUser().setAuthenticatedSubjectIdentifier(sequenceConfig
                        .getAuthenticatedUser().getUsernameAsSubjectIdentifier(sequenceConfig.getApplicationConfig()
                                .isUseUserstoreDomainInLocalSubjectIdentifier(), sequenceConfig.getApplicationConfig
                                ().isUseTenantDomainInLocalSubjectIdentifier()));
            }

        }

        sequenceConfig.getAuthenticatedUser().setUserAttributes(authenticatedUserAttributes);

    }

    /**
     * Compute the user store which user to be provisioned
     *
     * @return
     * @throws org.wso2.carbon.user.core.UserStoreException
     */
    private String getUserStoreDomain(String userStoreDomain, UserRealm realm)
            throws FrameworkException, org.wso2.carbon.user.core.UserStoreException {

        // If the any of above value is invalid, keep it empty to use primary userstore
        if (userStoreDomain != null
                && realm.getUserStoreManager().getSecondaryUserStoreManager(userStoreDomain) == null) {
            throw new FrameworkException("Specified user store domain " + userStoreDomain
                    + " is not valid.");
        }

        return userStoreDomain;
    }


    private UserStoreManager getUserStoreManager(UserRealm realm, String userStoreDomain)
            throws org.wso2.carbon.user.core.UserStoreException, FrameworkException {
        UserStoreManager userStoreManager;
        if (userStoreDomain != null && !userStoreDomain.isEmpty()) {
            userStoreManager = realm.getUserStoreManager().getSecondaryUserStoreManager(
                    userStoreDomain);
        } else {
            userStoreManager = realm.getUserStoreManager();
        }

        if (userStoreManager == null) {
            throw new FrameworkException("Specified user store is invalid");
        }
        return userStoreManager;
    }

    private String getMissingClaims(String subjectIdentifier, AuthenticationContext context, List<String> mappedRoles,
                                    Map<String, String> extAttributesValueMap) throws FrameworkException {

        // IdP claims mapped to local claim dialect: extAttributesValueMap
        // Check with external endpoint and validate which are missing user claims
        // Format should be string that contains claim URIs in comma separated way

        try {
            // START: Demonstrate read claim vlaue of admin
            RealmService realmService = JITAccountAssociatorServiceComponent.getRealmService();
            UserRealm realm = (UserRealm) realmService.getTenantUserRealm(IdentityTenantUtil.getTenantId(context.getTenantDomain()));
            String claimValue = realm.getUserStoreManager().getUserClaimValue(realm.getRealmConfiguration().getAdminUserName(), "http://wso2.org/claims/url", null);
            // END: Demonstrate read claim vlaue of admin

            // Use Test values
            String TEST_CLAIMS = "http://wso2.org/claims/country,http://wso2.org/claims/displayName,http://wso2.org/claims/mobile";
            return TEST_CLAIMS;
        } catch (UserStoreException e) {
            throw new FrameworkException("Error while loading tenant user realm to enrich claims", e);
        }

    }


}
