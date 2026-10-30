/**
 * The ICAP server on Netty: the shared engine, the per-connection state machine, the channel pipeline and the Turkish
 * block texts. Request-thread code: no blocking I/O, no logging, no control-plane calls (architecture-tests fences).
 */
package io.rwsafe.dataplane.server;
