plugins {
    kotlin("jvm") version "2.0.21"
    application
    `maven-publish`
    signing
}

group = "io.tenova"
version = "0.1.0"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
    withSourcesJar()
    withJavadocJar()
}

application {
    mainClass.set("io.tenova.swt3.Swt3Kt")
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            groupId = "io.tenova"
            artifactId = "swt3-ai"
            version = project.version.toString()
            from(components["java"])

            pom {
                name.set("SWT3 AI Witness SDK")
                description.set("Cryptographic attestation for AI inference. 108 procedures, 56 namespaces, 8 languages, 31 frameworks. EU AI Act, NIST AI RMF, CMMC, SR 11-7.")
                url.set("https://sovereign.tenova.io")
                licenses {
                    license {
                        name.set("Apache-2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0")
                    }
                }
                developers {
                    developer {
                        id.set("tenova")
                        name.set("Tenable Nova LLC")
                        email.set("engineering@tenovaai.com")
                    }
                }
                scm {
                    connection.set("scm:git:https://github.com/tenova-labs/swt3-ai.git")
                    developerConnection.set("scm:git:https://github.com/tenova-labs/swt3-ai.git")
                    url.set("https://github.com/tenova-labs/swt3-ai")
                }
            }
        }
    }
    repositories {
        maven {
            name = "local"
            url = uri(layout.buildDirectory.dir("repo"))
        }
    }
}

signing {
    useGpgCmd()
    sign(publishing.publications["maven"])
}
