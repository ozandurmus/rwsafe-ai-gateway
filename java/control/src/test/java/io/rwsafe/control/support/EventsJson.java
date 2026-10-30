package io.rwsafe.control.support;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Instant;
import java.util.UUID;

/** Batches in the data plane's exact wire shape ({@code VerdictEventJson}), with synthetic identities. */
public final class EventsJson {

    private static final ObjectMapper JSON = new ObjectMapper();

    private EventsJson() {
    }

    public static ObjectNode event(String platform, String verdict, String userClaim, String address) {
        String id = UUID.randomUUID().toString();
        ObjectNode e = JSON.createObjectNode();
        e.put("eventId", id);
        e.put("receivedAt", Instant.now().minusSeconds(5).toString());
        e.put("service", "reqmod");
        e.put("platform", platform);
        e.put("surface", "web");
        e.put("step", "chat");
        e.put("verdict", verdict);
        if (verdict.equals("ALLOW")) {
            e.putNull("reason");
        } else {
            e.put("reason", "customer_data");
        }
        ArrayNode findings = e.putArray("findings");
        if (verdict.equals("REDACT")) {
            findings.addObject().put("class", "TCKN").put("count", 2);
        }
        e.put("bodyBytes", 1024);
        e.put("decisionMicros", 180);
        e.put("userClaim", userClaim);
        e.put("clientAddress", address);
        e.put("transport", "plain_allowlisted");
        e.put("snapshotVersion", 1);
        e.put("correlationId", id);
        return e;
    }

    public static String batch(ObjectNode... events) {
        ArrayNode a = JSON.createArrayNode();
        for (ObjectNode e : events) {
            a.add(e);
        }
        return a.toString();
    }
}
