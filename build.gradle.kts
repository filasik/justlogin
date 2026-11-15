plugins {
    java
    id("com.gradleup.shadow") version "9.6.1" apply false
    id("xyz.jpenilla.run-paper") version "3.1.0" apply false
    id("com.modrinth.minotaur") version "2.+" apply false
    id("io.papermc.hangar-publish-plugin") version "0.1.4"
}

// Changelog text of the current version only (the "## [<version>]" section of CHANGELOG.md)
val releaseNotes: Provider<String> = providers.fileContents(layout.projectDirectory.file("CHANGELOG.md")).asText.map { text ->
    val version = project.property("pluginVersion") as String
    val section = text.lineSequence()
        .dropWhile { !it.startsWith("## [$version]") }
        .drop(1).takeWhile { !it.startsWith("## ") }
        .joinToString("\n").trim()
    section.ifEmpty { throw GradleException("CHANGELOG.md has no section '## [$version]'") }
}
extra["releaseNotes"] = releaseNotes

subprojects {
    apply(plugin = "java")

    group = "me.skerik"
    version = rootProject.property("pluginVersion") as String

    repositories {
        mavenCentral()
        maven("https://repo.papermc.io/repository/maven-public/")
        maven("https://oss.sonatype.org/content/repositories/snapshots")
    }

    java {
        toolchain.languageVersion = JavaLanguageVersion.of(25)
    }

    tasks.withType<JavaCompile>().configureEach {
        options.encoding = "UTF-8"
        // Compile Java 21 bytecode across all modules (runs on MC 1.21.7+ Java 21 and MC 26.x Java 25)
        options.release = 21
        options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror"))
    }

    tasks.withType<Test>().configureEach {
        useJUnitPlatform()
        exclude("**/* *")
        jvmArgs("--enable-native-access=ALL-UNNAMED")
        doFirst {
            project.layout.buildDirectory.asFile.get().walkTopDown()
                .filter { it.isFile && it.name.contains(' ') }
                .forEach { it.delete() }
        }
        testLogging {
            events("failed")
            exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
        }
    }
}

// Hangar: ONE version with one jar per platform (Paper/Velocity/Waterfall).
// Publish with: ./gradlew publishPluginPublicationToHangar  (env HANGAR_API_TOKEN, permission create_version)
evaluationDependsOnChildren()

fun jarOf(module: String) =
    project(":$module").tasks.named<org.gradle.api.tasks.bundling.AbstractArchiveTask>("shadowJar").flatMap { it.archiveFile }

fun versionsOf(key: String) =
    providers.gradleProperty(key).map { v -> v.split(",").map(String::trim).filter(String::isNotEmpty) }

hangarPublish {
    publications.register("plugin") {
        version.set(project.property("pluginVersion") as String)
        id.set(project.property("hangarId") as String)
        channel.set("Release") // must exist on Hangar
        changelog.set(releaseNotes)
        apiKey.set(providers.environmentVariable("HANGAR_API_TOKEN"))
        platforms {
            register(io.papermc.hangarpublishplugin.model.Platforms.PAPER) {
                jar.set(jarOf("paper"))
                platformVersions.set(versionsOf("hangarPaperVersions"))
            }
            register(io.papermc.hangarpublishplugin.model.Platforms.VELOCITY) {
                jar.set(jarOf("velocity"))
                platformVersions.set(versionsOf("hangarVelocityVersions"))
            }
            register(io.papermc.hangarpublishplugin.model.Platforms.WATERFALL) {
                jar.set(jarOf("bungee"))
                platformVersions.set(versionsOf("hangarWaterfallVersions"))
            }
        }
    }
}
