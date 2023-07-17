# Keycloak Microsoft Active Directory User SID Mapper

A keycloak extension to get the SID from Active directory LDAP.

# Requirements

- Keycloak v21.*

# Installation 

To install, just place the jar file in the  ```/providers``` folder in your keycloak install (or mount it if you're using a container). Then run the build commend (```kc.sh build```). Then start your keycloak application.
You'll find the mapper available as a mapper for a LDAP User Federation in your Keycloak instance.
Th name of the mapper is ```msad-user-sid-ldap-mapper``` (in the *Mapper Type* field)