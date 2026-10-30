package io.rwsafe.platform.content;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a type that holds request or response content (a prompt, a response chunk, an uploaded file, a header value
 * that can carry identity). The logging fence (AGENTS.md 4.14) requires such a type to be a class, not a record, and to
 * declare its own {@code toString()} that reads no {@link BodyContent} accessor, so the object is safe to print.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface BodyBearing {
}
