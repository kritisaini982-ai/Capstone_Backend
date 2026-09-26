FROM eclipse-temurin:17-jre

WORKDIR /app

ENV GRYPE_DB_MAX_ALLOWED_BUILT_AGE=720h

COPY --from=anchore/syft:v1.52.0 /syft /usr/local/bin/syft
COPY --from=anchore/grype:v0.119.0 /grype /usr/local/bin/grype

COPY build/libs/backend-0.0.1-SNAPSHOT.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]