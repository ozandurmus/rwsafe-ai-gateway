/**
 * Process wiring of the data plane: configuration at start-up, the Netty bootstrap, the control-plane client threads.
 * Never on a request thread. Every other data-plane package except {@code controlplane} is request-thread code.
 */
package io.rwsafe.dataplane.boot;
