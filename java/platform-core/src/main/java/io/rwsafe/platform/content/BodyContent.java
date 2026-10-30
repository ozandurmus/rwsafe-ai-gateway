package io.rwsafe.platform.content;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks an accessor that returns raw content of a {@link BodyBearing} type. The logging fence (AGENTS.md 4.14) forbids a
 * class that calls such an accessor from depending on any logging API or the standard streams: code that reads content
 * returns derived features, classes, digests and counts, and a different class logs those.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface BodyContent {
}
