CREATE TABLE roles
(
    id        SERIAL PRIMARY KEY,
    authority VARCHAR(100) NOT NULL UNIQUE
);

CREATE TABLE users
(
    id         SERIAL PRIMARY KEY,
    name       VARCHAR(255) NOT NULL,
    username   VARCHAR(255) NOT NULL UNIQUE,
    email      VARCHAR(255) NOT NULL UNIQUE,
    password   VARCHAR(255) NOT NULL,
    is_enabled BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITHOUT TIME ZONE
);

CREATE TABLE users_roles
(
    user_fk INTEGER NOT NULL,
    role_fk INTEGER NOT NULL,
    PRIMARY KEY (user_fk, role_fk),
    FOREIGN KEY (user_fk) REFERENCES users (id),
    FOREIGN KEY (role_fk) REFERENCES roles (id)
);

CREATE TABLE password_recover_tokens
(
    id         SERIAL PRIMARY KEY,
    token      VARCHAR(50)              NOT NULL,
    email      VARCHAR(255)             NOT NULL,
    expiration TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);

INSERT INTO roles (authority)
VALUES ('ROLE_ADMIN'),
       ('ROLE_USER');

INSERT INTO users (name, username, email, password, is_enabled, created_at)
VALUES ('Geraldo Daroz', 'daroz', 'contato@daroz.dev', '$2a$10$TjnGx4y4dpqohmDEPscnvuhR1NBcWPrFtawnGxwRdw66fnFuwp3me',
        TRUE, NOW());
INSERT INTO users (name, username, email, password, is_enabled, created_at)
VALUES ('Michael Douglas', 'douglas', 'contato@mdouglas.dev',
        '$2a$10$TjnGx4y4dpqohmDEPscnvuhR1NBcWPrFtawnGxwRdw66fnFuwp3me', TRUE, NOW());

INSERT INTO users_roles (user_fk, role_fk)
VALUES (1, 1);
INSERT INTO users_roles (user_fk, role_fk)
VALUES (1, 2);
INSERT INTO users_roles (user_fk, role_fk)
VALUES (2, 1);
INSERT INTO users_roles (user_fk, role_fk)
VALUES (2, 2);