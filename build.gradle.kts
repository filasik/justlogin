plugins {
    java
    id("com.gradleup.shadow") version "9.6.1" apply false
    id("xyz.jpenilla.run-paper") version "3.1.0" apply false
    id("com.modrinth.minotaur") version "2.+" apply false
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
