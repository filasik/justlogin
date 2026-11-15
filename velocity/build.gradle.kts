plugins {
    id("com.gradleup.shadow")
    id("com.modrinth.minotaur")
}

val pluginNameProp = rootProject.property("pluginName") as String
val velocityApiVersionProp = rootProject.property("velocityApiVersion") as String

dependencies {
    implementation(project(":core"))
    implementation("com.zaxxer:HikariCP:${rootProject.property("hikariVersion")}") {
        exclude(group = "org.slf4j", module = "slf4j-api")
    }
    implementation("org.xerial:sqlite-jdbc:${rootProject.property("sqliteVersion")}") {
        exclude(group = "org.slf4j", module = "slf4j-api")
    }
    implementation("org.mariadb.jdbc:mariadb-java-client:${rootProject.property("mariadbVersion")}")
    implementation("com.password4j:password4j:${rootProject.property("password4jVersion")}") {
        exclude(group = "org.slf4j", module = "slf4j-api")
    }
    implementation("com.google.code.gson:gson:${rootProject.property("gsonVersion")}")
    implementation("org.jspecify:jspecify:${rootProject.property("jspecifyVersion")}")
    implementation("org.bstats:bstats-velocity:${rootProject.property("bstatsVersion")}")

    compileOnly("com.velocitypowered:velocity-api:$velocityApiVersionProp")

    testImplementation("com.velocitypowered:velocity-api:$velocityApiVersionProp")
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
    filesMatching(listOf("velocity-plugin.json", "build.properties")) {
        expand(props)
    }
}

tasks.shadowJar {
    archiveBaseName.set("${pluginNameProp}-Velocity")
    archiveClassifier.set("")
    duplicatesStrategy = DuplicatesStrategy.INCLUDE
    mergeServiceFiles()
    relocate("com.zaxxer.hikari", "me.skerik.justlogin.libs.hikari")
    relocate("com.password4j", "me.skerik.justlogin.libs.password4j")
    relocate("org.bstats", "me.skerik.justlogin.libs.bstats")
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
    loaders.addAll("velocity")
    @Suppress("UNCHECKED_CAST")
    changelog = rootProject.extra["releaseNotes"] as Provider<String>
}
