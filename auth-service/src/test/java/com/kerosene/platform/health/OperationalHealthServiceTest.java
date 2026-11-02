package com.kerosene.platform.health;

import com.kerosene.platform.config.production.ProductionProfileDetector;
import com.kerosene.platform.config.production.ProductionSafetyCheckChain;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.boot.availability.ApplicationAvailability;
import org.springframework.beans.factory.ObjectProvider;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;
import static org.assertj.core.api.Assertions.assertThat;

class OperationalHealthServiceTest {
    @Test @SuppressWarnings("unchecked")
    void authReadinessOnlyRequiresAuthOwnedTables() throws Exception {
        var jdbc = mock(JdbcTemplate.class);
        var connection = mock(Connection.class);
        var metadata = mock(DatabaseMetaData.class);
        var tables = mock(ResultSet.class);
        when(connection.getMetaData()).thenReturn(metadata);
        when(metadata.getTables(isNull(), anyString(), anyString(), any())).thenReturn(tables);
        when(tables.next()).thenReturn(true);
        doAnswer(invocation -> ((ConnectionCallback<?>) invocation.getArgument(0)).doInConnection(connection))
                .when(jdbc).execute(any(ConnectionCallback.class));
        var availability = mock(ApplicationAvailability.class);
        when(availability.getReadinessState()).thenReturn(org.springframework.boot.availability.ReadinessState.ACCEPTING_TRAFFIC);
        var service = new OperationalHealthService(jdbc, mock(StringRedisTemplate.class),
                availability, new MockEnvironment(), mock(ObjectProvider.class),
                mock(ObjectProvider.class), mock(ProductionProfileDetector.class),
                mock(ProductionSafetyCheckChain.class), mock(HealthMetricRecorder.class), "auth");
        assertThat(service.readiness().checks().get("schema").status()).isEqualTo("UP");
        verify(metadata, never()).getTables(any(), eq("financial"), any(), any());
        verify(metadata).getTables(isNull(), eq("auth"), eq("users_credentials"), any());
    }
}
