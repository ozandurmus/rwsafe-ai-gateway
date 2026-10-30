// detect: Tier-1 detector library (ARCHITECTURE.md §9). RE2/J is the only regular-expression engine on the inline path.
dependencies {
    api(project(":platform-core"))
    api(libs.re2j)
}
