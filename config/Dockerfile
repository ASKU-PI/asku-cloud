FROM maven:3.8.3-openjdk-17 AS build
COPY src /usr/src/app/src
COPY pom.xml /usr/src/app
RUN mvn -f /usr/src/app/pom.xml clean package

FROM openjdk:17
COPY --from=build /usr/src/app/target/config.jar /usr/app/config.jar
EXPOSE 8888
ENTRYPOINT ["java","-jar","/usr/app/config.jar"]

HEALTHCHECK --interval=30s --timeout=30s CMD curl -f http://localhost:8888/actuator/health || exit 1