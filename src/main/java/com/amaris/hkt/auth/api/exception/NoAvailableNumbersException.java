package com.amaris.hkt.auth.api.exception;

/**
 * Excepción lanzada cuando no hay números disponibles para generar
 * nuevos tickets en una lotería para una fecha específica.
 */
public class NoAvailableNumbersException extends RuntimeException {
    public NoAvailableNumbersException(String message) {
        super(message);
    }

    public NoAvailableNumbersException(String message, Throwable cause) {
        super(message, cause);
    }
}

