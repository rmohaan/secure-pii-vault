package com.example.investor.web;

import com.example.investor.crypto.CryptoFailure;
import com.example.investor.service.InvestorService.NotFound;
import org.springframework.dao.*;
import org.springframework.http.*;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

@RestControllerAdvice
public class ApiErrors {
    @ExceptionHandler({MethodArgumentNotValidException.class, HttpMessageNotReadableException.class, MethodArgumentTypeMismatchException.class})
    ResponseEntity<ProblemDetail> invalid(Exception e) { return error(400, "Invalid request"); }
    @ExceptionHandler(NotFound.class)
    ResponseEntity<ProblemDetail> missing() { return error(404, "Investor not found"); }
    @ExceptionHandler(DuplicateKeyException.class)
    ResponseEntity<ProblemDetail> duplicate() { return error(409, "Investor already exists"); }
    @ExceptionHandler({CryptoFailure.class, DataAccessException.class})
    ResponseEntity<ProblemDetail> unavailable(Exception e) { return error(503, "Required service unavailable"); }
    private ResponseEntity<ProblemDetail> error(int status, String detail) {
        return ResponseEntity.status(status).body(ProblemDetail.forStatusAndDetail(HttpStatus.valueOf(status), detail));
    }
}
