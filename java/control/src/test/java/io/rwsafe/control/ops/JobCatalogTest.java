package io.rwsafe.control.ops;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.type.filter.RegexPatternTypeFilter;
import org.springframework.scheduling.annotation.Scheduled;

/**
 * The Job log describes exactly what the server schedules: every {@code @Scheduled} method of the control plane is on
 * {@link ScheduledJobs}, and each one's schedule is the catalog's.
 */
class JobCatalogTest {

    @Test
    void everyScheduledMethodIsInScheduledJobsAndMatchesTheCatalog() throws Exception {
        ClassPathScanningCandidateComponentProvider scan = new ClassPathScanningCandidateComponentProvider(false);
        scan.addIncludeFilter(new RegexPatternTypeFilter(java.util.regex.Pattern.compile(".*")));
        List<String> elsewhere = new ArrayList<>();
        int classes = 0;
        for (BeanDefinition d : scan.findCandidateComponents("io.rwsafe.control")) {
            Class<?> c = Class.forName(d.getBeanClassName(), false, getClass().getClassLoader());
            if (c.getProtectionDomain().getCodeSource().getLocation().getPath().contains("/classes/java/test/")) {
                continue;
            }
            classes++;
            for (Method m : c.getDeclaredMethods()) {
                if (m.isAnnotationPresent(Scheduled.class) && c != ScheduledJobs.class) {
                    elsewhere.add(c.getSimpleName() + "." + m.getName());
                }
            }
        }
        assertTrue(classes > 40, "the scan found " + classes + " classes");
        assertTrue(elsewhere.isEmpty(), "scheduled methods outside ScheduledJobs: " + elsewhere);

        Map<String, String> described = new TreeMap<>();
        for (JobCatalog.Job j : JobCatalog.JOBS) {
            if (j.kind() != JobCatalog.Kind.CONTINUOUS) {
                described.put(j.id(), j.kind() == JobCatalog.Kind.CRON ? j.cron() + "@" + j.zone()
                    : j.initialDelay() + "/" + j.delay());
            }
        }
        Map<String, String> scheduled = new TreeMap<>();
        for (Method m : ScheduledJobs.class.getDeclaredMethods()) {
            Scheduled s = m.getAnnotation(Scheduled.class);
            if (s == null) {
                continue;
            }
            String id = switch (m.getName()) {
                case "snapshotResign" -> JobCatalog.SNAPSHOT_RESIGN;
                case "captureRetention" -> JobCatalog.CAPTURE_RETENTION;
                case "captureKeyReload" -> JobCatalog.CAPTURE_KEY_RELOAD;
                case "captureWatermark" -> JobCatalog.CAPTURE_WATERMARK;
                default -> "unlisted:" + m.getName();
            };
            scheduled.put(id, s.cron().isEmpty()
                ? Duration.parse(s.initialDelayString()) + "/" + Duration.parse(s.fixedDelayString())
                : s.cron() + "@" + s.zone());
        }
        assertEquals(described, scheduled);
        Set<String> ids = new HashSet<>();
        JobCatalog.JOBS.forEach(j -> assertTrue(ids.add(j.id()), "duplicate job id " + j.id()));
    }
}
