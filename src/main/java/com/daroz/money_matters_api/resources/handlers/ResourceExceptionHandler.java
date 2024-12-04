package com.daroz.money_matters_api.resources.handlers;

import com.daroz.money_matters_api.data.dtos.CustomErrorDTO;
import com.daroz.money_matters_api.services.exceptions.DatabaseException;
import com.daroz.money_matters_api.services.exceptions.ForbiddenException;
import com.daroz.money_matters_api.services.exceptions.ResourceNotFoundException;
import com.daroz.money_matters_api.services.exceptions.UnauthorizedException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.time.Instant;

@ControllerAdvice
public class ResourceExceptionHandler {

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<CustomErrorDTO> resourceNotFound(ResourceNotFoundException e, HttpServletRequest request) {
        HttpStatus status = HttpStatus.NOT_FOUND;
        CustomErrorDTO error = new CustomErrorDTO(Instant.now(),status.value(), e.getMessage(), request.getRequestURI());
        return ResponseEntity.status(status).body(error);
    }

    @ExceptionHandler(DatabaseException.class)
    public ResponseEntity<CustomErrorDTO> database(DatabaseException e, HttpServletRequest request) {
        HttpStatus status = HttpStatus.BAD_REQUEST;
        CustomErrorDTO error = new CustomErrorDTO(Instant.now(),status.value(), e.getMessage(), request.getRequestURI());
        return ResponseEntity.status(status).body(error);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<CustomErrorDTO> methodArgumentNotValid(MethodArgumentNotValidException e, HttpServletRequest request) {
        HttpStatus status = HttpStatus.UNPROCESSABLE_ENTITY;
        CustomErrorDTO error = new CustomErrorDTO(Instant.now(), status.value(), e.getBindingResult().getFieldErrors().get(0).getDefaultMessage(), request.getRequestURI());

        return ResponseEntity.status(status).body(error);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<CustomErrorDTO> illegalArgument(IllegalArgumentException e, HttpServletRequest request) {
        HttpStatus status = HttpStatus.BAD_REQUEST;
        CustomErrorDTO error = new CustomErrorDTO(Instant.now(),status.value(), e.getMessage(), request.getRequestURI());
        return ResponseEntity.status(status).body(error);
    }

    @ExceptionHandler(ForbiddenException.class)
    public ResponseEntity<CustomErrorDTO> forbidden(ForbiddenException e, HttpServletRequest request) {
        HttpStatus status = HttpStatus.FORBIDDEN;
        CustomErrorDTO error = new CustomErrorDTO(Instant.now(),status.value(), e.getMessage(), request.getRequestURI());
        return ResponseEntity.status(status).body(error);
    }

    @ExceptionHandler(UnauthorizedException.class)
    public ResponseEntity<CustomErrorDTO> unauthorized(UnauthorizedException e, HttpServletRequest request) {
        HttpStatus status = HttpStatus.UNAUTHORIZED;
        CustomErrorDTO error = new CustomErrorDTO(Instant.now(),status.value(), e.getMessage(), request.getRequestURI());
        return ResponseEntity.status(status).body(error);
    }

}
