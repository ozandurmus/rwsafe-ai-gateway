/**
 * Verdict events (metadata only) and the bounded, non-blocking queue request threads hand them to. The control-plane
 * client in {@code io.rwsafe.dataplane.controlplane} drains the queue on its own thread.
 */
package io.rwsafe.dataplane.events;
