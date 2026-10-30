package io.rwsafe.architecture.fixtures.inline.controlplane;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/** Runs on its own thread in the product; the request-thread fence exempts this package. */
public final class SnapshotClient {

    private final HttpClient http = HttpClient.newHttpClient();

    public void refresh() {
        http.sendAsync(HttpRequest.newBuilder(URI.create("http://snapshot.example.invalid/")).build(),
            HttpResponse.BodyHandlers.discarding());
    }
}
