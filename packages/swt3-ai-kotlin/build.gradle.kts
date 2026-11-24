plugins {
    kotlin("jvm") version "2.0.21"
    application
    `maven-publish`
    signing
}

group = "io.tenova"
version = "8.3.0"

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
                description.set("Cryptographic attestation for AI inference. 294 procedures, 10 namespaces, 11 languages, 98 frameworks. EU AI Act, NIST AI RMF, CMMC, SR 11-7, DORA, OWASP MCP Top 10.")
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
        maven {
            name = "OSSRH"
            url = uri("https://s01.oss.sonatype.org/service/local/staging/deploy/maven2/")
            credentials {
                username = findProperty("ossrhUsername") as String? ?: ""
                password = findProperty("ossrhPassword") as String? ?: ""
            }
        }
        maven {
            name = "CentralPortal"
            url = uri("https://central.sonatype.com/api/v1/publisher/deployments/download/")
            credentials {
                username = findProperty("centralToken") as String? ?: ""
                password = findProperty("centralTokenPassword") as String? ?: ""
            }
        }
    }
}

signing {
    useGpgCmd()
    sign(publishing.publications["maven"])
}
