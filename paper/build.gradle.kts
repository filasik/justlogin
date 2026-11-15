plugins {
    id("com.gradleup.shadow")
    id("xyz.jpenilla.run-paper")
    id("com.modrinth.minotaur")
}

val pluginNameProp = rootProject.property("pluginName") as String
val pluginDescProp = rootProject.property("pluginDescription") as String
val pluginMainProp = rootProject.property("pluginMain") as String
val pluginLoaderProp = rootProject.property("pluginLoader") as String
val pluginWebsiteProp = rootProject.property("pluginWebsite") as String
val apiVersionProp = rootProject.property("apiVersion") as String
val minecraftVersionProp = rootProject.property("minecraftVersion") as String
val paperApiVersionProp = rootProject.property("paperApiVersion") as String
val bstatsIdProp = rootProject.property("bstatsId") as String

dependencies {
    implementation(project(":core"))
    implementation(project(":editor"))
    implementation("org.bstats:bstats-bukkit:${rootProject.property("bstatsVersion")}")

    compileOnly("io.papermc.paper:paper-api:$paperApiVersionProp")
    compileOnly("io.netty:netty-transport:${rootProject.property("nettyVersion")}")
    compileOnly("com.zaxxer:HikariCP:${rootProject.property("hikariVersion")}")
    compileOnly("org.xerial:sqlite-jdbc:${rootProject.property("sqliteVersion")}")
    compileOnly("org.mariadb.jdbc:mariadb-java-client:${rootProject.property("mariadbVersion")}")
    compileOnly("com.password4j:password4j:${rootProject.property("password4jVersion")}")
    compileOnly("org.apache.logging.log4j:log4j-core:${rootProject.property("log4jVersion")}")

    testImplementation("io.papermc.paper:paper-api:$paperApiVersionProp")
    testImplementation("io.netty:netty-transport:${rootProject.property("nettyVersion")}")
    testImplementation("org.apache.logging.log4j:log4j-core:${rootProject.property("log4jVersion")}")
    testImplementation("com.zaxxer:HikariCP:${rootProject.property("hikariVersion")}")
    testImplementation("org.xerial:sqlite-jdbc:${rootProject.property("sqliteVersion")}")
    testImplementation("com.password4j:password4j:${rootProject.property("password4jVersion")}")
    testImplementation("org.slf4j:slf4j-simple:2.0.17")
    testImplementation(platform("org.junit:junit-bom:6.1.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<JavaCompile>().configureEach {
    // Log4j2 jars reference optional SpotBugs/Bnd compileOnly annotations missing from Maven runtime transitives
    options.compilerArgs.add("-Xlint:-classfile")
}

tasks.processResources {
    filteringCharset = "UTF-8"
    val props = mapOf(
        "version" to project.version.toString(),
        "pluginName" to pluginNameProp,
        "pluginDescription" to pluginDescProp,
        "pluginMain" to pluginMainProp,
        "pluginLoader" to pluginLoaderProp,
        "pluginWebsite" to pluginWebsiteProp,
        "apiVersion" to apiVersionProp,
        "bstatsId" to bstatsIdProp,
        "sqliteVersion" to rootProject.property("sqliteVersion").toString(),
        "mariadbVersion" to rootProject.property("mariadbVersion").toString(),
        "hikariVersion" to rootProject.property("hikariVersion").toString(),
        "password4jVersion" to rootProject.property("password4jVersion").toString(),
    )
    inputs.properties(props)
    filesMatching(listOf("paper-plugin.yml", "build.properties", "libraries.txt")) {
        expand(props)
    }
}

tasks.shadowJar {
    archiveBaseName.set(pluginNameProp)
    archiveClassifier.set("")
    relocate("org.bstats", "me.skerik.justlogin.libs.bstats")
    dependencies {
        exclude(dependency("org.jspecify:.*"))
        exclude(dependency("com.google.code.gson:.*"))
        exclude(dependency("com.google.errorprone:.*"))
    }
}

tasks.jar {
    enabled = false
}

tasks.build {
    dependsOn(tasks.shadowJar)
}

tasks.runServer {
    minecraftVersion(minecraftVersionProp)
    jvmArgs("-Dcom.mojang.eula.agree=true")
}

// Modrinth: one version per platform (same version number). Loaders apply to the whole
// version, so each jar must be its own version. Run :paper:modrinth, :velocity:modrinth, :bungee:modrinth.
modrinth {
    token = System.getenv("MODRINTH_TOKEN")
    projectId = rootProject.property("modrinthId") as String
    versionNumber = project.version as String
    versionType = "release"
    uploadFile.set(tasks.shadowJar)
    gameVersions.addAll("1.21.7", "1.21.8", "1.21.11", "26.1.2", minecraftVersionProp)
    loaders.addAll("paper", "purpur", "folia")
    @Suppress("UNCHECKED_CAST")
    changelog = rootProject.extra["releaseNotes"] as Provider<String>
    syncBodyFrom = providers.fileContents(rootProject.layout.projectDirectory.file("docs/modrinth.md")).asText
}
