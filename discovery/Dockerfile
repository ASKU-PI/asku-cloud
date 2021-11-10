FROM maven:3.8.3-openjdk-17 AS build

COPY pom.xml .

RUN mvn -B dependency:go-offline

COPY src src

RUN mvn -B package -DskipTests

FROM openjdk:17
COPY --from=build target/discovery.jar .
EXPOSE 8761
ENTRYPOINT ["java", "-jar", "discovery.jar"]

HEALTHCHECK --interval=30s --timeout=30s CMD curl -f http://localhost:8761/actuator/health || exit 1