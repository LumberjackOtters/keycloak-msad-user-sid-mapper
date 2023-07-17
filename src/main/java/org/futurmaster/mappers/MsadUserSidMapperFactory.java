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

import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.UserStorageProviderModel;
import org.keycloak.storage.ldap.LDAPConfig;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapperFactory;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.LDAPConfigDecorator;

import java.util.List;

/**
 * @author <a href="mailto:lalung.alexandre@gmail.com">PurpleBabar</a>
 */
public class MsadUserSidMapperFactory extends AbstractLDAPStorageMapperFactory implements LDAPConfigDecorator {

    public static final String PROVIDER_ID = "msad-user-sid-ldap-mapper";
    protected static final List<ProviderConfigProperty> configProperties;

    static {
        List<ProviderConfigProperty> props = getConfigProps(null);
        configProperties = props;
    }

    static List<ProviderConfigProperty> getConfigProps(ComponentModel p) {
        UserStorageProviderModel parent = new UserStorageProviderModel();

        ProviderConfigurationBuilder config = ProviderConfigurationBuilder.create()
                .property().name(MsadUserSidMapper.USER_MODEL_ATTRIBUTE)
                .label("User Model Attribute")
                .helpText("Name of the UserModel property or attribute you want to map the LDAP attribute into. For example 'firstName', 'lastName, 'email', 'street' etc.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add();

        return config.build();
    }

    @Override
    public String getHelpText() {
        return "Used to map objectSID from LDAP user to attribute of UserModel (ObjectSID is a Binary attribute and is always read from LDAP)";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel config) throws ComponentValidationException {

    }

    @Override
    protected AbstractLDAPStorageMapper createMapper(ComponentModel mapperModel, LDAPStorageProvider federationProvider) {
        return new MsadUserSidMapper(mapperModel, federationProvider);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties(RealmModel realm, ComponentModel parent) {
        return getConfigProps(parent);
    }

    @Override
    public void updateLDAPConfig(LDAPConfig ldapConfig, ComponentModel mapperModel) {
        ldapConfig.addBinaryAttribute(MsadUserSidMapper.LDAP_ATTRIBUTE_NAME);
    }
}