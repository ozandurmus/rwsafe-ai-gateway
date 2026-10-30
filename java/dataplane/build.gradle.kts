// dataplane: Netty ICAP server and LLM gateway (ARCHITECTURE.md §3.1). Never depends on persistence, control or worker;
// no JDBC and no Spring MVC on its classpath (AGENTS.md section 5, SR-DP-6).
dependencies {
    implementation(project(":platform-core"))
    implementation(project(":detect"))
    implementation(project(":policy"))
}
