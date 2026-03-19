package com.amaris.hkt.auth.api.exception;

public class ResourceNotFoundException extends RuntimeException {
    public ResourceNotFoundException(String resource, Object id) {
        super(String.format("%s con id '%s' no encontrado", resource, id));
    }
}
