package io.rwsafe.architecture.fixtures.inline;

import java.sql.Connection;
import java.sql.SQLException;

public final class JdbcInspector {

    public boolean inspect(Connection connection) throws SQLException {
        return connection.isValid(1);
    }
}
