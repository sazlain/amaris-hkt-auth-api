-- Script de creación de tablas para la base de datos de autenticación
-- Nota: Hibernate creará estas tablas automáticamente con ddl-auto=update
-- Este script es solo como referencia

-- Tabla de tokens revocados (blacklist)
-- Se llena cuando un usuario hace logout para invalidar su JWT
CREATE TABLE IF NOT EXISTS revoked_tokens (
    revoked_token_id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    token VARCHAR(1024) NOT NULL UNIQUE,
    expiry_date TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_revoked_tokens_user FOREIGN KEY (user_id)
        REFERENCES users(user_id) ON DELETE CASCADE
);

-- Crear índices para búsquedas rápidas
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_user_id ON revoked_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_token ON revoked_tokens(token);

-- Tabla de refresh tokens
CREATE TABLE IF NOT EXISTS refresh_tokens (
    refresh_token_id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    token VARCHAR(512) NOT NULL UNIQUE,
    expiry_date TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_refresh_tokens_user FOREIGN KEY (user_id)
        REFERENCES users(user_id) ON DELETE CASCADE
);

-- Tabla de usuarios
CREATE TABLE IF NOT EXISTS users (
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT users_role_check CHECK (role IN ('ADMIN', 'USER'))
);

