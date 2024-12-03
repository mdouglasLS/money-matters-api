package com.daroz.money_matters_api.data.enums;

public enum RolesENUM {
    ADMIN("ROLE_ADMIN"),
    USER("ROLE_USER");

    private final String value;

    RolesENUM(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
