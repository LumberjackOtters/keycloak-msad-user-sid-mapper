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

package org.futurmaster.mappers;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.LDAPConstants;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.ModelException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.UserModelDelegate;
import org.keycloak.models.utils.reflection.Property;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.LDAPUtils;
import org.keycloak.storage.ldap.idm.model.LDAPObject;
import org.keycloak.storage.ldap.idm.query.Condition;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQuery;

import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapper;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.regex.Pattern;
import java.util.regex.MatchResult;
import java.lang.Integer;
import java.lang.Long;
import java.lang.StringBuilder;

/**
 * Mapper specific to MSAD. It's able to read the objectSID and store it in an attribute.
 *
 * @author <a href="mailto:lalung.alexandre@gmail.com">PurpleBabar</a>
 */
public class MsadUserSidMapper extends AbstractLDAPStorageMapper {

    private static final Logger logger = Logger.getLogger(MsadUserSidMapper.class);

    private static final Map<String, Property<Object>> userModelProperties = LDAPUtils.getUserModelProperties();

    public static final String USER_MODEL_ATTRIBUTE = "user.model.attribute";
    public static final String LDAP_ATTRIBUTE_NAME = "ObjectSID";

    public MsadUserSidMapper(ComponentModel mapperModel, LDAPStorageProvider ldapProvider) {
        super(mapperModel, ldapProvider);
    }

    @Override
    public void onImportUserFromLDAP(LDAPObject ldapUser, UserModel user, RealmModel realm, boolean isCreate) {
        String userModelAttrName = getUserModelAttribute();
        String ldapAttrName = getLdapAttributeName();

        // We won't update binary attributes to Keycloak DB. They might be too big
        if (isBinaryAttribute()) {
            return;
        }
    }

    @Override
    public void onRegisterUserToLDAP(LDAPObject ldapUser, UserModel localUser, RealmModel realm) {
        String userModelAttrName = getUserModelAttribute();
        String ldapAttrName = getLdapAttributeName();

        // The ObjectSID will be created by the AD so we don't need to register anything when creating the user.

        ldapUser.addReadOnlyAttributeName(ldapAttrName);
    }

    @Override
    public Set<String> mandatoryAttributeNames() {
        boolean isMandatoryInLdap = isMandatoryInLdap();
        return isMandatoryInLdap? Collections.singleton(getLdapAttributeName()) : null;
    }

    @Override
    public UserModel proxy(final LDAPObject ldapUser, UserModel delegate, RealmModel realm) {
        final String userModelAttrName = getUserModelAttribute();
        final String ldapAttrName = getLdapAttributeName();
        boolean isAlwaysReadValueFromLDAP = isReadOnly();
        final boolean isMandatoryInLdap = isMandatoryInLdap();
        final boolean isBinaryAttribute = isBinaryAttribute();

        if (isBinaryAttribute) {

            delegate = new UserModelDelegate(delegate) {

                @Override
                public void setSingleAttribute(String name, String value) {
                    if (name.equalsIgnoreCase(userModelAttrName)) {
                        logSkipDBWrite();
                    } else {
                        super.setSingleAttribute(name, value);
                    }
                }

                @Override
                public void setAttribute(String name, List<String> values) {
                    if (name.equalsIgnoreCase(userModelAttrName)) {
                        logSkipDBWrite();
                    } else {
                        super.setAttribute(name, values);
                    }
                }

                @Override
                public void removeAttribute(String name) {
                    if (name.equalsIgnoreCase(userModelAttrName)) {
                        logSkipDBWrite();
                    } else {
                        super.removeAttribute(name);
                    }
                }

                private void logSkipDBWrite() {
                    logger.debugf("Skip writing model attribute '%s' to DB for user '%s' as it is mapped to binary LDAP attribute", userModelAttrName, getUsername());
                }

            };

        }

        // We prefer to read attribute value from LDAP instead of from local Keycloak DB
        if (isAlwaysReadValueFromLDAP) {

            delegate = new UserModelDelegate(delegate) {

                @Override
                public String getFirstAttribute(String name) {
                    if (name.equalsIgnoreCase(userModelAttrName)) {
                        String ldapAttrRawValue = ldapUser.getAttributeAsString(ldapAttrName);                    
                        return getSIDfromldapAttrRawValue(ldapAttrRawValue);
                    } else {
                        return super.getFirstAttribute(name);
                    }
                }

                @Override
                public Stream<String> getAttributeStream(String name) {
                    if (name.equalsIgnoreCase(userModelAttrName)) {
                        Collection<String> ldapAttrRawCollectionValue = ldapUser.getAttributeAsSet(ldapAttrName);
                        if (ldapAttrRawCollectionValue == null) {
                            return Stream.empty();
                        } else {
                            Collection<String> ldapAttrValue = new ArrayList<String>();
                            for (String ldapAttrRawValue : ldapAttrRawCollectionValue) {
                                ldapAttrValue.add(getSIDfromldapAttrRawValue(ldapAttrRawValue));
                            }
                            return ldapAttrValue.stream();
                        }
                    } else {
                        return super.getAttributeStream(name);
                    }
                }

                @Override
                public Map<String, List<String>> getAttributes() {
                    Map<String, List<String>> attrs = new HashMap<>(super.getAttributes());

                    Set<String> allLdapAttrRawValues = ldapUser.getAttributeAsSet(ldapAttrName);
                    if (allLdapAttrRawValues != null) {
                        Set<String> allLdapAttrValues = new HashSet<String>();
                        for (String ldapAttrRawValue : allLdapAttrRawValues) {
                            allLdapAttrValues.add(getSIDfromldapAttrRawValue(ldapAttrRawValue));
                        }
                        attrs.put(userModelAttrName, new ArrayList<>(allLdapAttrValues));
                    } else {
                        attrs.remove(userModelAttrName);
                    }
                    return attrs;
                }

            };
        }

        return delegate;
    }

    @Override
    public void beforeLDAPQuery(LDAPQuery query) {
        String userModelAttrName = getUserModelAttribute();
        String ldapAttrName = getLdapAttributeName();

        // Add mapped attribute to returning ldap attributes
        query.addReturningLdapAttribute(ldapAttrName);
        if (isReadOnly()) {
            query.addReturningReadOnlyLdapAttribute(ldapAttrName);
        }

        // Change conditions and use ldapAttribute instead of userModel
        for (Condition condition : query.getConditions()) {
            condition.updateParameterName(userModelAttrName, ldapAttrName);
            String parameterName = condition.getParameterName();
            if (parameterName != null && (parameterName.equalsIgnoreCase(userModelAttrName) || parameterName.equalsIgnoreCase(ldapAttrName))) {
                condition.setBinary(isBinaryAttribute());
            }
        }
    }

    private String getAttributeDefaultValue() {
        return LDAPConstants.EMPTY_ATTRIBUTE_VALUE;
    }

    private String getUserModelAttribute() {
        return mapperModel.getConfig().getFirst(USER_MODEL_ATTRIBUTE);
    }

    String getLdapAttributeName() {
        return LDAP_ATTRIBUTE_NAME;
    }

    private boolean isBinaryAttribute() {
        return true;
    }

    private boolean isReadOnly() {
        return true;
    }

    private boolean isMandatoryInLdap() {
        return false;
    }

    protected void setPropertyOnUserModel(Property<Object> userModelProperty, UserModel user, String ldapAttrValue) {
        if (ldapAttrValue == null) {
            userModelProperty.setValue(user, null);
        } else {
            Class<Object> clazz = userModelProperty.getJavaClass();

            if (String.class.equals(clazz)) {
                userModelProperty.setValue(user, ldapAttrValue);
            } else if (Boolean.class.equals(clazz) || boolean.class.equals(clazz)) {
                Boolean boolVal = Boolean.valueOf(ldapAttrValue);
                userModelProperty.setValue(user, boolVal);
            } else {
                logger.warnf("Don't know how to set the property '%s' on user '%s' . Value of LDAP attribute is '%s' ", userModelProperty.getName(), user.getUsername(), ldapAttrValue.toString());
            }
        }
    }

    public String decodeBase64toHex(String encoded){
        byte[] decoded = Base64.decodeBase64(encoded);
        String hexString = Hex.encodeHexString(decoded);

        return hexString;
    }

    public List<String> splitHex(String text) {
        return Pattern.compile(".{1,2}")
         .matcher(text)
         .results()
         .map(MatchResult::group)
         .collect(Collectors.toList());
    }

    public String decodeSidFromSplittedValue(List<String> hexArray) {
        StringBuilder sid = new StringBuilder("S-");

        try{
            // Getting revision
            String revision = String.valueOf(hexArray.get(0));
            sid.append(String.valueOf(Long.parseLong(revision,16)));
            sid.append("-");

            int subAuthorityCounts = Integer.parseInt(hexArray.get(1));

            String identifierAuthority = String.join("", hexArray.subList(2, 8));
            sid.append(String.valueOf(Integer.parseInt(identifierAuthority)));
            sid.append("-");

            List<String> machineIds = new ArrayList<String>();
            for (int i = 0; i < subAuthorityCounts; i++) {
                List<String> machineIdList = hexArray.subList(8+(i*4), 12+(i*4));
                Collections.reverse(machineIdList);
                machineIds.add(String.valueOf(Long.parseLong(String.join("", machineIdList),16)));
            }

            sid.append(String.join("-", machineIds));

        } catch(Exception e ){
            logger.warnf("Error Trying to decode some wrong value for the ObjectSID");
        }

        return sid.toString();
    }

    public String getSIDfromldapAttrRawValue(String ldapAttrRawValue){
        String decodedLdapAttrValue = decodeBase64toHex(ldapAttrRawValue);
        List<String> splittedLdapAttrValue = splitHex(decodedLdapAttrValue);
        String sidValue = decodeSidFromSplittedValue(splittedLdapAttrValue);

        return sidValue;
    }
}