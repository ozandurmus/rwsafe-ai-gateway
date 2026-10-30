/**
 * The only data-plane package that talks to the control plane: the signed snapshot pull (8091) and the capture and
 * verdict event sink (8092), both on their own threads behind bounded queues. Request-thread code never depends on this
 * package and never performs network or disk I/O (architecture-tests fences, AGENTS.md section 5).
 */
package io.rwsafe.dataplane.controlplane;
