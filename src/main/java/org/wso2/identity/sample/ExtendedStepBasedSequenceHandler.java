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

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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
import org.wso2.carbon.identity.user.profile.mgt.UserProfileAdmin;
import org.wso2.carbon.identity.user.profile.mgt.UserProfileException;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Calls for JIT Provisioning before checks for user associations
 */
public class ExtendedStepBasedSequenceHandler extends DefaultStepBasedSequenceHandler {

    private static final Log log = LogFactory.getLog(ExtendedStepBasedSequenceHandler.class);

    @SuppressWarnings("unchecked")
    protected void handlePostAuthentication(HttpServletRequest request,
                                            HttpServletResponse response, AuthenticationContext context)
            throws FrameworkException {

        if (log.isDebugEnabled()) {
            log.debug("Handling Post Authentication tasks");
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
}
