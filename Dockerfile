FROM quay.io/keycloak/keycloak
COPY ldap-msad-user-sid-mapper.jar /opt/keycloak/providers/
