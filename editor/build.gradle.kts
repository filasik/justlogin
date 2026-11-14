dependencies {
    implementation(project(":core"))
    compileOnly("org.jspecify:jspecify:${rootProject.property("jspecifyVersion")}")
    compileOnly("com.google.code.gson:gson:${rootProject.property("gsonVersion")}")

    testImplementation(project(":core"))
    testImplementation("org.jspecify:jspecify:${rootProject.property("jspecifyVersion")}")
    testImplementation("com.google.code.gson:gson:${rootProject.property("gsonVersion")}")
    testImplementation("com.zaxxer:HikariCP:${rootProject.property("hikariVersion")}")
    testImplementation("com.password4j:password4j:${rootProject.property("password4jVersion")}")
    testImplementation("org.xerial:sqlite-jdbc:${rootProject.property("sqliteVersion")}")
    testImplementation("org.slf4j:slf4j-simple:2.0.17")
    testImplementation(platform("org.junit:junit-bom:6.1.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
