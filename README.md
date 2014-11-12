# LDAP Authentication Provider

## Description
The LDAP Authentication provider can be used to perform Authentication against LDAP providers such as Active Directory.
It is based on the Spring Security LDAP component which offers a lot of customization options.
All options are configured in the backbase.properties

The LDAP Authentication provider offers the following features:

- Authentication against LDAP services
- Configurable user search filter
- Configurable group serach filter
- Automatic Backbase user creation
- Automatic Backsase group creation
- Updating user - group mappings
- Configurable LDAP authorities to Portal group mapping
- Configurable LDAP user properties to Backbase User properties  mapping
- Can be configured to do authentication only


## Setup Instructions
Collect information about the LDAP environment you want to integrate with. You'll need to following information

- LDAP Server location
- LDAP User with Bind Access for querying the LDAP (required for Active Directory)

Depending on the environment and LDAP schema your can optionally configure

- LDAP user search base. You can limit the part on which the users can be found in the LDAP schema
- LDAP user search filter. You can configure the ldap schema property on which you want to match
- LDAP group seach fitler. You can limit the part on which the groups can be found in the LDAP schema
- LDAP group search base. You can configure the filter which is used to find the group



### backbase.properties
Add the following properties to the backbase.properties

    # LDAP HOSTS (space delimited)
    ldap.host=ldap://ADSERVER1:389 ldap://ADSERVER2.389
    ldap.root=

    # LDAP User with bind access
    ldap.userDn=username@domain
    ldap.password=password

    # Base DN
    ldap.user.search.base=
    ldap.user.search.filter=(&(sAMAccountName={0})(objectclass=user))
    ldap.group.search.base=
    ldap.group.search.filter=(&(objectclass=group)(member={0}))


    # Only Perform Authentication
    ldap.authenticate.only=true

    # Throw Exception if not exist

    # Create User if not exist
    ldap.user.create=false

    # Enable newly created users
    ldap.user.enable=true

    # Map User Properties
    ldap.user.mapping.attributes=true
    ldap.user.mapping.attribute.displayName=displayName
    ldap.user.mapping.attribute.cn=commonName
    ldap.user.mapping.store=false

    # Default LDAP group if no authorities are found
    ldap.group.create=true
    ldap.group.update=false
    ldap.group.assign.default=true
    ldap.group.default=manager

    # Mapping of LDAP Authorities to portal groups.
    # LDAP Authorities are converted from ROLE_ADMIN to role.admin to enable the lookup in properties files.
    ldap.group.mapping.role.admin=admin
    ldap.group.mapping.role.manager=manager
    ldap.group.mapping.role.user=user

###backbase-portal-business-security.xml
Add the authentication provider to the backbase-portal-busines-security.xml


    <?xml version="1.0" encoding="UTF-8"?>
    <beans:beans xmlns="http://www.springframework.org/schema/security" xmlns:beans="http://www.springframework.org/schema/beans" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans-3.1.xsd http://www.springframework.org/schema/security  http://www.springframework.org/schema/security/spring-security.xsd">

        <ldap-server id="ldap-server" url="${ldap.host}" root="${ldap.root}" manager-dn="${ldap.userDn}" manager-password="${ldap.password}" />


        <!-- Configure Authentication mechanism -->
        <authentication-manager alias="authenticationManager">
            <ldap-authentication-provider user-search-filter="${ldap.user.search.filter}" user-search-base="${ldap.user.search.base}" group-search-filter="${ldap.group.search.filter}" group-search-base="${ldap.group.search.base}"
                        user-context-mapper-ref="userDetailsContextMapper">
            </ldap-authentication-provider>
            <authentication-provider user-service-ref="portalUserDetailsService">
                <password-encoder ref="passwordEncoder" />
            </authentication-provider>

        </authentication-manager>

        <beans:bean id="userDetailsContextMapper" class="com.backbase.extensions.security.ldap.LdapUserDetailsContextMapper">
            <beans:constructor-arg index="0" ref="userService" />
            <beans:constructor-arg index="1" ref="groupService" />
            <beans:constructor-arg index="2" ref="backbaseConfiguration" />
        </beans:bean>


    </beans:beans>



### Support

- Backbase Portal 5.5.x


### Dependency Reference
Add the following dependency to the portalserver pom file

    <dependency>
        <groupId>com.backbase.extensions.mosaic-security</groupId>
        <artifactId>authentication-provider-ldap</artifactId>
        <version>1.1-RELEASE</version>
    </dependency>

## Technical type
- BE (Back end)

## Bundle Category
- Security
