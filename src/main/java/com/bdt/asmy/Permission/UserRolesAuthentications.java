package com.bdt.asmy.Permission;

import lombok.Getter;


@Getter
public enum UserRolesAuthentications {
    USER_PERMISSIONS("user:read"),
    // ROLE_HR("user:read", "user:update"),
    MANAGER_PERMISSIONS("user:read", "user:update"),
    ADMIN_PERMISSIONS("user:read", "user:create", "user:update"),
    ROLE_SUPER_ADMIN("user:read", "user:create", "user:update", "user:delete");

    private final String[] authorities;

    UserRolesAuthentications(String... authorities) {
        this.authorities = authorities;
    }

}
