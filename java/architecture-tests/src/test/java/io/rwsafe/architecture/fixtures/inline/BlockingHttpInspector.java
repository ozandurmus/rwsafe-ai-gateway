package io.rwsafe.architecture.fixtures.inline;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

public final class BlockingHttpInspector {

    public int inspect(URL url) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        return connection.getResponseCode();
    }
}
