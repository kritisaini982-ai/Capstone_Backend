# =========================
# Stage 1: Build Spring Boot
# =========================
FROM eclipse-temurin:17-jdk AS builder

WORKDIR /workspace

COPY gradlew gradlew
COPY gradle gradle
COPY build.gradle settings.gradle ./
COPY src src

RUN chmod +x gradlew
RUN ./gradlew clean bootJar --no-daemon


# =========================
# Stage 2: Runtime
# =========================
FROM eclipse-temurin:17-jre

WORKDIR /app

COPY --from=anchore/syft:v1.52.0 /syft /usr/local/bin/syft
COPY --from=anchore/grype:v0.119.0 /grype /usr/local/bin/grype

# Download Grype vulnerability database into the image
RUN mkdir -p /root/.cache/grype/db \
    && grype db update

# Prevent runtime database auto-updates
ENV GRYPE_DB_AUTO_UPDATE=false
ENV GRYPE_DB_MAX_ALLOWED_BUILT_AGE=720h

COPY --from=builder /workspace/build/libs/backend-0.0.1-SNAPSHOT.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]