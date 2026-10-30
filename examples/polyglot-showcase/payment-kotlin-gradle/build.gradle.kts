plugins {
    kotlin("jvm") version "1.9.22"
}

dependencies {
    implementation("com.fasterxml.jackson.core:jackson-databind:${jacksonVersion}")
    implementation("io.ktor:ktor-server-core:${ktorVersion}")
}
