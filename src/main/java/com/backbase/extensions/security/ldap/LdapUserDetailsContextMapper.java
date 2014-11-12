package com.backbase.extensions.security.ldap;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.userdetails.UserDetailsContextMapper;

import com.backbase.portal.commons.configuration.BackbaseConfiguration;
import com.backbase.portal.foundation.business.service.GroupBusinessService;
import com.backbase.portal.foundation.business.service.UserBusinessService;
import com.backbase.portal.foundation.commons.exceptions.FoundationDataException;
import com.backbase.portal.foundation.commons.exceptions.FoundationReadOnlyException;
import com.backbase.portal.foundation.commons.exceptions.FoundationRuntimeException;
import com.backbase.portal.foundation.commons.exceptions.ItemAlreadyExistsException;
import com.backbase.portal.foundation.commons.exceptions.ItemNotFoundException;
import com.backbase.portal.foundation.domain.conceptual.StringPropertyValue;
import com.backbase.portal.foundation.domain.conceptual.UserPropertyDefinition;
import com.backbase.portal.foundation.domain.model.Group;
import com.backbase.portal.foundation.domain.model.Role;
import com.backbase.portal.foundation.domain.model.User;

/**
 * User: bartv
 * Date: 04-02-14
 * Time: 12:00
 */
public class LdapUserDetailsContextMapper implements UserDetailsContextMapper {

    private static final Logger LOG = LoggerFactory.getLogger(LdapUserDetailsContextMapper.class);
    private final BackbaseConfiguration backbaseConfiguration;

    private UserBusinessService userBusinessService;
    private GroupBusinessService groupBusinessService;

    private final boolean autoCreateUsers;
    private final boolean autoCreateGroup;
    private final boolean onlyPerformAuthentication;
    private final boolean storeLdapAttributes;
    private final boolean updateLdapGroups;
    private final boolean enableNewlyCreatedUsers;
    private final boolean mapLdapAttributes;
    private final boolean enableUserForCurrentSession;

    public LdapUserDetailsContextMapper(UserBusinessService userBusinessService,
            GroupBusinessService groupBusinessService, BackbaseConfiguration backbaseConfiguration) {
        this.userBusinessService = userBusinessService;
        this.groupBusinessService = groupBusinessService;
        this.backbaseConfiguration = backbaseConfiguration;

        this.autoCreateGroup = backbaseConfiguration.getBoolean("ldap.group.create", true);
        this.autoCreateUsers = backbaseConfiguration.getBoolean("ldap.user.create", true);
        this.enableNewlyCreatedUsers = backbaseConfiguration.getBoolean("ldap.user.enable", true);
        this.onlyPerformAuthentication = backbaseConfiguration.getBoolean("ldap.authenticate.only", false);
        this.storeLdapAttributes = backbaseConfiguration.getBoolean("ldap.user.mapping.store", false);
        this.updateLdapGroups = backbaseConfiguration.getBoolean("ldap.group.update", false);
        this.mapLdapAttributes = backbaseConfiguration.getBoolean("ldap.user.mapping.attributes", false);
        this.enableUserForCurrentSession = backbaseConfiguration.getBoolean("ldap.user.enable.session", false);
    }

    /**
     * Creates a fully populated UserDetails object for use by the security framework.
     */
    public UserDetails mapUserFromContext(DirContextOperations ctx, String userName,
            Collection<? extends GrantedAuthority> authorities) {
        LOG.info("Mapping user {} from context {} with authorities {}", new Object[] {userName, ctx, authorities});

        debugLdapAttributes(ctx);

        String password = UUID.randomUUID().toString();

        // Map the LDAP group(s) to Portal Groups
        List<Group> groups = mapLdapAuthoritiesToGroups(authorities);

        // Map the LDAP user to a Portal User
        User user = null;
        try {
            user = userBusinessService.getUser(userName);
            if (onlyPerformAuthentication) {
                LOG.info("Only performing authentication. Returning user: {} defined in portal manager",
                        user.getUsername());
            } else {
                if (mapLdapAttributes && storeLdapAttributes == true) {
                    LOG.info("Updating Ldap Attributes for user: {}", user.getUsername());
                    mapLdapAttributes(user, ctx);
                }

                if (updateLdapGroups) {
                    LOG.info("Updating groups for user: {}", user.getUsername());

                    // First remote all groups
                    user.getGroups().clear();

                    // Add grousp from LDAP to user
                    user.getGroups().addAll(groups);
                    userBusinessService.updateUser(user.getUsername(), user);
                }
            }

        } catch (ItemNotFoundException e) {
            if (autoCreateUsers) {

                if (groups.isEmpty()) {
                    throw new AuthenticationServiceException("Cannot create user becuase no groups are assigned");
                }
                user = registerUser(userName, password, ctx, groups);
            } else {
                throw new AuthenticationCredentialsNotFoundException(
                        "User is not allowed to login because the user does not exist in the portal database. ");
            }
        } catch (FoundationReadOnlyException e) {
            throw new AuthenticationServiceException("Unable to persist user");
        } catch (FoundationDataException e) {
            throw new AuthenticationServiceException("Unable to persist user");
        }

        if (mapLdapAttributes == true && storeLdapAttributes == false) {
            mapLdapAttributes(user, ctx);
        }

        if(enableUserForCurrentSession) {
            user.setEnabled(true);
        }

        debugUserAuthorities(user);


        return user;
    }

    private User registerUser(String userName, String password, DirContextOperations ctx, List<Group> groups) {
        LOG.info("Registering user {} with groups {}", userName, groups);

        User user;
        user = new User();
        user.setUsername(userName);
        user.setPassword(password);
        user.setEnabled(enableNewlyCreatedUsers);
        user.getGroups().addAll(groups);
        if (mapLdapAttributes && storeLdapAttributes == false) {
            LOG.info("Creating Ldap Attributes for user: {}", user.getUsername());
            mapLdapAttributes(user, ctx);
        }

        try {
            userBusinessService.createUser(user);
        } catch (FoundationDataException e1) {
            throw new FoundationRuntimeException(e1);
        } catch (ItemNotFoundException e1) {
            throw new FoundationRuntimeException(e1);
        } catch (ItemAlreadyExistsException e1) {
            throw new FoundationRuntimeException(e1);
        }
        return user;
    }

    private void mapLdapAttributes(User user, DirContextOperations ctx) {
        // not yet implemented

    }

    /**
     * Creates a propertyDefinition for email on the {@link User} object and sets the value.
     *
     * @param user The {@link User} object for which to set an email property
     * @param email The email address of the user
     */
    private void setEmail(User user, String email) {
        if (email != null) {
            UserPropertyDefinition emailProperty = new UserPropertyDefinition("email", new StringPropertyValue(email));
            user.getPropertyDefinitions().put("email", emailProperty);
        }
    }

    /**
     * Reverse of the above operation. Populates a context object from the supplied user object.
     */
    public void mapUserToContext(UserDetails user, DirContextAdapter ctx) {
        throw new IllegalStateException("Only retrieving data from LDAP is currently supported");
    }

    private List<Group> mapLdapAuthoritiesToGroups(Collection<? extends GrantedAuthority> authorities) {

        LOG.info("map LDAP Authorities {} to groups", authorities);

        List<Group> groups = new ArrayList<Group>();

        if (authorities != null && !authorities.isEmpty()) {
            Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
            LOG.info("Authorities:");
            while (iterator.hasNext()) {
                GrantedAuthority authority = iterator.next();
                String authorityName = authority.getAuthority();

                String ldapGroupName = authorityName.replace(' ', '.');
                String[] portalGroupNames = backbaseConfiguration.getStringArray("ldap.group.mapping." + ldapGroupName);
                LOG.info("Retrieving backbase group mapping for ldap authority: {} using property name: {}",
                        authorityName, portalGroupNames);

                if (portalGroupNames != null) {
                    for (String portalGroupName : portalGroupNames) {
                        Group group = getPortalGroup(portalGroupName.trim(), authorityName);
                        if (group != null) {
                            LOG.info("\tConverted " + authority.toString() + " to group " + group.getName());
                            groups.add(group);
                        }

                    }
                } else {
                    LOG.info("No backbase group found for authority: " + authorityName);
                }
            }
        } else {
            LOG.warn("No authorities found.");
        }

        if (backbaseConfiguration.getBoolean("ldap.group.assign.default", false)) {
            String portalGroupName = backbaseConfiguration.getString("ldap.group.default");
            if (StringUtils.isEmpty(portalGroupName)) {
                LOG.warn("Cannot assign default group, because there is no group defined in backbase.properties");
            } else {
                Group group = getPortalGroup(portalGroupName, null);
                if (group != null) {
                    groups.add(group);
                    LOG.info("Added default group: {} to list of groups");
                }

            }
        }
        return groups;
    }

    private Group getPortalGroup(String portalGroupName, String ldapAuthority) {
        LOG.info("Get portal group for name: {}", portalGroupName);

        Group group = null;
        try {
            group = groupBusinessService.getGroup(portalGroupName);
            LOG.info("Group {}", group);
        } catch (ItemNotFoundException e) {
            LOG.info("ItemNotFoundException! Create new group {}", portalGroupName);

            if (autoCreateGroup) {

                group = new Group();
                if (ldapAuthority != null)
                    group.setDescription(
                            "Group " + portalGroupName + " created automatically form LDAP Authority: "
                                    + ldapAuthority
                    );
                else {
                    group.setDescription("");
                }
                group.setName(portalGroupName);
                group.setRole(Role.USER);
                try {
                    groupBusinessService.createGroup(group);

                } catch (ItemAlreadyExistsException e1) {
                    throw new FoundationRuntimeException(e1);
                } catch (FoundationDataException e1) {
                    throw new FoundationRuntimeException(e1);
                }
            } else {
                LOG.info("Cannot create group for: {}", portalGroupName);
            }
        }
        return group;
    }

    private void debugLdapAttributes(final DirContextOperations ctx) {
        NamingEnumeration<? extends Attribute> attributes = ctx.getAttributes().getAll();
        try {
            while (attributes.hasMore()) {
                Attribute attribute = attributes.next();
                LOG.info("attribute id={}, {}", attribute.getID(), attribute.toString());
            }
        } catch (NamingException e) {
            LOG.error(e.getMessage(), e);
        }
    }

    private void debugUserAuthorities(final User user) {
        Iterator<? extends GrantedAuthority> iterator = user.getAuthorities().iterator();
        LOG.info("Mapped User Authorities:");
        while (iterator.hasNext()) {
            GrantedAuthority authority = iterator.next();
            String authorityName = authority.getAuthority();
            LOG.info("\tauthorityName={}", authorityName);
        }
    }
}
