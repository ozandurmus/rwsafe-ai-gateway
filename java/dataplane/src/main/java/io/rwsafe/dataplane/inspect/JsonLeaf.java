package io.rwsafe.dataplane.inspect;

import io.rwsafe.platform.content.BodyBearing;
import io.rwsafe.platform.content.BodyContent;

/**
 * One JSON leaf that can carry text: a string (key or value; raw span includes the quotes) or a number (raw span is the
 * number), with its decoded text.
 */
@BodyBearing
public final class JsonLeaf {

    private final int rawStart;
    private final int rawEnd;
    private final String text;
    private final boolean number;

    JsonLeaf(int rawStart, int rawEnd, String text, boolean number) {
        this.rawStart = rawStart;
        this.rawEnd = rawEnd;
        this.text = text;
        this.number = number;
    }

    public boolean number() {
        return number;
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
