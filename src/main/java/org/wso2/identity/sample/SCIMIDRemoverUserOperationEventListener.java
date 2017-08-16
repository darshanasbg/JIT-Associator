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

import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonException;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.core.util.AnonymousSessionUtil;
import org.wso2.carbon.core.util.PermissionUpdateUtil;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.handler.provisioning.impl.DefaultProvisioningHandler;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.AbstractIdentityUserOperationEventListener;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.user.profile.mgt.UserProfileAdmin;
import org.wso2.carbon.identity.user.profile.mgt.UserProfileException;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserOperationEventListener;
import org.wso2.carbon.user.core.ldap.ActiveDirectoryUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.identity.sample.internal.SCIMIDRemoverServiceComponent;

import java.security.SecureRandom;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Avoid manually updating auto-generated attributes in the Active Directory
 */
public class SCIMIDRemoverUserOperationEventListener extends AbstractIdentityUserOperationEventListener {


    private static Log log = LogFactory.getLog(SCIMIDRemoverUserOperationEventListener.class);
    public static final String ID_URI = "urn:scim:schemas:core:1.0:id";
    public static final String META_CREATED_URI = "urn:scim:schemas:core:1.0:meta.created";
    public static final String META_LAST_MODIFIED_URI = "urn:scim:schemas:core:1.0:meta.lastModified";
    public static final String META_LOCATION_URI = "urn:scim:schemas:core:1.0:meta.location";

    @Override
    public boolean doPreAddUser(String userName, Object credential, String[] roleList, Map<String, String> claims, String profile, UserStoreManager userStoreManager) throws UserStoreException {
        log.info("doPreAddUser()");
        try {
            if (!isEnable() || !userStoreManager.isSCIMEnabled()) {
                return true;
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new UserStoreException("Error while reading isScimEnabled from userstore manager", e);
        }

        if (!(userStoreManager instanceof ActiveDirectoryUserStoreManager)) {
            return true;
        }

        log.info("removing scim: " + SCIMIDRemoverUserOperationEventListener.ID_URI);
        claims.remove(SCIMIDRemoverUserOperationEventListener.ID_URI);
        log.info("removing scim: " + SCIMIDRemoverUserOperationEventListener.META_CREATED_URI);
        claims.remove(SCIMIDRemoverUserOperationEventListener.META_CREATED_URI);
        log.info("removing scim: " + SCIMIDRemoverUserOperationEventListener.META_LAST_MODIFIED_URI);
        claims.remove(SCIMIDRemoverUserOperationEventListener.META_LAST_MODIFIED_URI);
        log.info("removing scim: " + SCIMIDRemoverUserOperationEventListener.META_LOCATION_URI);
        claims.remove(SCIMIDRemoverUserOperationEventListener.META_LOCATION_URI);

        return true;
    }


    @Override
    public boolean doPostAddUser(String userName, Object credential, String[] roleList, Map<String, String> claims, String profile, UserStoreManager userStoreManager) throws UserStoreException {
        log.info("doPostAddUser()");
        try {
            if (!isEnable() || !userStoreManager.isSCIMEnabled()) {
                return true;
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new UserStoreException("Error while reading isScimEnabled from userstore manager", e);
        }

        if (!(userStoreManager instanceof ActiveDirectoryUserStoreManager)) {
            return true;
        }

        claims.put(SCIMIDRemoverUserOperationEventListener.ID_URI, "11-4322-4322");
        return true;
    }


    @Override
    public boolean doPreSetUserClaimValues(String userName, Map<String, String> claims,
                                           String profileName, UserStoreManager userStoreManager)
            throws UserStoreException {
        try {
            if (!isEnable() || !userStoreManager.isSCIMEnabled()) {
                return true;
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new UserStoreException("Error while reading isScimEnabled from userstore manager", e);
        }


        if (!(userStoreManager instanceof ActiveDirectoryUserStoreManager)) {
            return true;
        }

        log.info("removing scim claim: " + SCIMIDRemoverUserOperationEventListener.META_LAST_MODIFIED_URI);
        claims.remove(SCIMIDRemoverUserOperationEventListener.META_LAST_MODIFIED_URI);
        return true;
    }

    @Override
    public boolean doPostGetUserClaimValues(String userName, String[] claims, String profileName,
                                            Map<String, String> claimMap, UserStoreManager userStoreManager)
            throws UserStoreException {
        try {
            if (!isEnable() || !userStoreManager.isSCIMEnabled()) {
                return true;
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new UserStoreException("Error while reading isScimEnabled from userstore manager", e);
        }

        if (!(userStoreManager instanceof ActiveDirectoryUserStoreManager)) {
            return true;
        }

        if (claimMap.containsKey(SCIMIDRemoverUserOperationEventListener.META_CREATED_URI)) {
            String createdTime = claimMap.get(SCIMIDRemoverUserOperationEventListener.META_CREATED_URI);

            try {
                log.info(">>>>>>>>>>>>>>>>>>>>>>>>>>> Before: " + SCIMIDRemoverUserOperationEventListener.META_CREATED_URI + " : " + createdTime);
                String formattedDate = convertDateTimeFormat(createdTime);
                log.info(">>>>>>>>>>>>>>>>>>>>>>>>>>> After: " + SCIMIDRemoverUserOperationEventListener.META_CREATED_URI + " : " + formattedDate);
                claimMap.put(SCIMIDRemoverUserOperationEventListener.META_CREATED_URI, formattedDate);
            } catch (ParseException e) {
                log.error(">>>>>>>>>>>>>>>>>>>>>>>>>>> Error while converting claim: "
                        + SCIMIDRemoverUserOperationEventListener.META_CREATED_URI, e);
            }
        }

        if (claimMap.containsKey(SCIMIDRemoverUserOperationEventListener.META_LAST_MODIFIED_URI)) {
            String modifiedTime = claimMap.get(SCIMIDRemoverUserOperationEventListener.META_LAST_MODIFIED_URI);

            try {
                log.info(">>>>>>>>>>>>>>>>>>>>>>>>>>> Before: " + SCIMIDRemoverUserOperationEventListener.META_LAST_MODIFIED_URI + " : " + modifiedTime);
                String formattedDate = convertDateTimeFormat(modifiedTime);
                log.info(">>>>>>>>>>>>>>>>>>>>>>>>>>> After: " + SCIMIDRemoverUserOperationEventListener.META_LAST_MODIFIED_URI + " : " + formattedDate);
                claimMap.put(SCIMIDRemoverUserOperationEventListener.META_LAST_MODIFIED_URI, formattedDate);
            } catch (ParseException e) {
                log.error(">>>>>>>>>>>>>>>>>>>>>>>>>>> Error while converting claim: "
                        + SCIMIDRemoverUserOperationEventListener.META_LAST_MODIFIED_URI, e);
            }
        }

        return true;
    }

    private String convertDateTimeFormat(String createdTime) throws ParseException {
        DateFormat originalFormat = new SimpleDateFormat("yyyyMMddHHmmss.SX");
        DateFormat targetFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
        Date date = originalFormat.parse(createdTime);
        return targetFormat.format(date);
    }


    @Override
    public int getExecutionOrderId() {
        int orderId = getOrderId();
        if (orderId != IdentityCoreConstants.EVENT_LISTENER_ORDER_ID) {
            return orderId;
        }
        return 91;
    }

}
