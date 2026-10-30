/**
 * jOOQ access, Flyway migrations and trigger-backed audit for the control plane and the worker (Q-16). Never on the
 * data-plane classpath. Every stored row is metadata (ADR-009 C1, C2, C6, C7): no prompt or response body, no raw
 * identity claim and no raw client address reaches this package.
 */
package io.rwsafe.persistence;
