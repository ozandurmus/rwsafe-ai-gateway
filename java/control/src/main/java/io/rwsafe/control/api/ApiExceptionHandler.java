package io.rwsafe.control.api;

import io.rwsafe.control.config.BodyLimitFilter;
import io.rwsafe.control.policy.RegistryRefusal;
import io.rwsafe.control.privacy.MaskingUnavailableException;
import org.jooq.exception.DataAccessException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

/** Maps failures to {@link ApiError}; names the parameter, never its value, and logs the exception class only. */
@RestControllerAdvice
public class ApiExceptionHandler {

    private static final Logger LOG = LoggerFactory.getLogger(ApiExceptionHandler.class);

    @ExceptionHandler(BadRequest.class)
    ResponseEntity<ApiError> badRequest(BadRequest e) {
        return ResponseEntity.badRequest().body(ApiError.of(e.reason(), e.getMessage()));
    }

    @ExceptionHandler(NotFound.class)
    ResponseEntity<ApiError> notFound(NotFound e) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ApiError.of(e.reason(), e.getMessage()));
    }

    @ExceptionHandler(RegistryRefusal.class)
    ResponseEntity<ApiError> registry(RegistryRefusal e) {
        return ResponseEntity.status(e.status()).body(ApiError.of(e.reason(), e.getMessage()));
    }

    @ExceptionHandler(io.rwsafe.control.capture.CaptureReadController.CaptureRefusal.class)
    ResponseEntity<ApiError> capture(io.rwsafe.control.capture.CaptureReadController.CaptureRefusal e) {
        return ResponseEntity.status(e.status()).body(ApiError.of(e.reason(), e.getMessage()));
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    ResponseEntity<ApiError> typeMismatch(MethodArgumentTypeMismatchException e) {
        return ResponseEntity.badRequest().body(ApiError.of("INVALID_PARAMETER",
            "The parameter '" + e.getName() + "' has an invalid value."));
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    ResponseEntity<ApiError> missing(MissingServletRequestParameterException e) {
        return ResponseEntity.badRequest().body(ApiError.of("MISSING_PARAMETER",
            "The parameter '" + e.getParameterName() + "' is required."));
    }

    @ExceptionHandler(BodyLimitFilter.BodyTooLargeException.class)
    ResponseEntity<ApiError> tooLarge(BodyLimitFilter.BodyTooLargeException e) {
        return ResponseEntity.status(HttpStatus.CONTENT_TOO_LARGE).body(ApiError.of("BODY_TOO_LARGE",
            "The request body is larger than this route accepts."));
    }

    @ExceptionHandler({HttpMessageNotReadableException.class, com.fasterxml.jackson.core.JacksonException.class})
    ResponseEntity<ApiError> unreadable(Exception e) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t instanceof BodyLimitFilter.BodyTooLargeException tooLarge) {
                return tooLarge(tooLarge);
            }
        }
        return ResponseEntity.badRequest().body(ApiError.of("INVALID_JSON",
            "The request body is not the expected JSON (unknown, missing or mistyped fields are refused)."));
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    ResponseEntity<ApiError> mediaType(HttpMediaTypeNotSupportedException e) {
        return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).body(ApiError.of("UNSUPPORTED_MEDIA_TYPE",
            "Send application/json."));
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    ResponseEntity<ApiError> method(HttpRequestMethodNotSupportedException e) {
        return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED).body(ApiError.of("METHOD_NOT_ALLOWED",
            "This route does not accept " + e.getMethod() + "."));
    }

    @ExceptionHandler(NoResourceFoundException.class)
    ResponseEntity<ApiError> noRoute(NoResourceFoundException e) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ApiError.of("NOT_FOUND", "No such route."));
    }

    @ExceptionHandler(MaskingUnavailableException.class)
    ResponseEntity<ApiError> masking(MaskingUnavailableException e) {
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(ApiError.of("MASKING_UNAVAILABLE",
            "The privacy key or the masking dictionary is missing; nothing is stored or served masked."));
    }

    @ExceptionHandler(DataAccessException.class)
    ResponseEntity<ApiError> database(DataAccessException e) {
        LOG.warn("database access failed: {}", e.getClass().getSimpleName());
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(ApiError.of("DATABASE_UNAVAILABLE",
            "The control-plane database did not answer."));
    }

    @ExceptionHandler(Exception.class)
    ResponseEntity<ApiError> other(Exception e) {
        // The class and the first product frame locate the defect; the message may carry data and is never logged.
        LOG.error("request failed: {} at {}", e.getClass().getName(), productFrame(e));
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(ApiError.of("INTERNAL",
            "The control plane failed on this request."));
    }

    static String productFrame(Throwable e) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            for (StackTraceElement frame : t.getStackTrace()) {
                if (frame.getClassName().startsWith("io.rwsafe.")) {
                    return frame.getClassName() + "." + frame.getMethodName() + ":" + frame.getLineNumber();
                }
            }
        }
        return "no product frame";
    }

    /** A request the API refuses, with its reason class. */
    public static final class BadRequest extends RuntimeException {

        private static final long serialVersionUID = 1L;
        private final String reason;

        public BadRequest(String reason, String message) {
            super(message);
            this.reason = reason;
        }

        public String reason() {
            return reason;
        }
    }

    public static final class NotFound extends RuntimeException {

        private static final long serialVersionUID = 1L;
        private final String reason;

        public NotFound(String reason, String message) {
            super(message);
            this.reason = reason;
        }

        public String reason() {
            return reason;
        }
    }
}
