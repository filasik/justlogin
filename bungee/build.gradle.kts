plugins {
    id("com.gradleup.shadow")
    id("com.modrinth.minotaur")
}

val pluginNameProp = rootProject.property("pluginName") as String
val bungeeApiVersionProp = rootProject.property("bungeeApiVersion") as String

dependencies {
    implementation(project(":core"))
    implementation("com.zaxxer:HikariCP:${rootProject.property("hikariVersion")}")
    implementation("org.xerial:sqlite-jdbc:${rootProject.property("sqliteVersion")}")
    implementation("org.mariadb.jdbc:mariadb-java-client:${rootProject.property("mariadbVersion")}")
    implementation("com.password4j:password4j:${rootProject.property("password4jVersion")}")
    implementation("org.jspecify:jspecify:${rootProject.property("jspecifyVersion")}")
    implementation("org.bstats:bstats-bungeecord:${rootProject.property("bstatsVersion")}")

    compileOnly("net.md-5:bungeecord-api:$bungeeApiVersionProp")

    testImplementation("net.md-5:bungeecord-api:$bungeeApiVersionProp")
    testImplementation("org.slf4j:slf4j-simple:2.0.17")
    testImplementation(platform("org.junit:junit-bom:6.1.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<JavaCompile>().configureEach {
    options.compilerArgs.add("-Xlint:-classfile")
}

tasks.processResources {
    filteringCharset = "UTF-8"
    val props = mapOf(
        "version" to project.version.toString(),
        "pluginName" to pluginNameProp,
        "pluginDescription" to rootProject.property("pluginDescription").toString(),
        "pluginWebsite" to rootProject.property("pluginWebsite").toString(),
        "bstatsId" to rootProject.property("bstatsId").toString(),
    )
    inputs.properties(props)
    filesMatching(listOf("bungee.yml", "build.properties")) {
        expand(props)
    }
}

tasks.shadowJar {
    archiveBaseName.set("${pluginNameProp}-Bungee")
    archiveClassifier.set("")
    duplicatesStrategy = DuplicatesStrategy.INCLUDE
    mergeServiceFiles()
    relocate("com.zaxxer.hikari", "me.skerik.justlogin.libs.hikari")
    relocate("com.password4j", "me.skerik.justlogin.libs.password4j")
    relocate("org.bstats", "me.skerik.justlogin.libs.bstats")
    relocate("org.slf4j", "me.skerik.justlogin.libs.slf4j")
}

tasks.jar {
    enabled = false
}

tasks.build {
    dependsOn(tasks.shadowJar)
}

modrinth {
    token = System.getenv("MODRINTH_TOKEN")
    projectId = rootProject.property("modrinthId") as String
    versionNumber = project.version as String
    versionType = "release"
    uploadFile.set(tasks.shadowJar)
    gameVersions.addAll("1.21.7", "1.21.8", "1.21.11", "26.1.2", rootProject.property("minecraftVersion") as String)
    loaders.addAll("bungeecord", "waterfall")
    @Suppress("UNCHECKED_CAST")
    changelog = rootProject.extra["releaseNotes"] as Provider<String>
}
