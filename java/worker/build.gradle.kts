// worker: async classifiers, SIEM out, retention, exports, SNMP, mail (ARCHITECTURE.md §3.3).
dependencies {
    implementation(project(":platform-core"))
    implementation(project(":detect"))
    implementation(project(":policy"))
    implementation(project(":persistence"))
}
