package dev.overlax.springsecuritysamples.model;

public enum Permission {
    DEVELOPERS_READ("developer:read"),
    DEVELOPERS_WRITE("developer:write");

    private final String permissions;

    Permission(String permissions) {
        this.permissions = permissions;
    }

    public String getPermissions() {
        return permissions;
    }
}
