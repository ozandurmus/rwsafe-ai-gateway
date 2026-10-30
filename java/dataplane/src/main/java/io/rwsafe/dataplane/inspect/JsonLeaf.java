package io.rwsafe.dataplane.inspect;

import io.rwsafe.platform.content.BodyBearing;
import io.rwsafe.platform.content.BodyContent;

/** One JSON string (key or value): its raw byte span including the quotes, and its decoded text. */
@BodyBearing
public final class JsonLeaf {

    private final int rawStart;
    private final int rawEnd;
    private final String text;

    JsonLeaf(int rawStart, int rawEnd, String text) {
        this.rawStart = rawStart;
        this.rawEnd = rawEnd;
        this.text = text;
    }

    public int rawStart() {
        return rawStart;
    }

    public int rawEnd() {
        return rawEnd;
    }

    @BodyContent
    public String text() {
        return text;
    }

    @Override
    public String toString() {
        return "JsonLeaf[" + rawStart + ".." + rawEnd + "]";
    }
}
