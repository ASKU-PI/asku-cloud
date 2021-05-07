FROM openjdk:11

ADD ./target/discovery.jar /app/
CMD ["java", "-Xmx200m", "-jar", "/app/discovery.jar"]

EXPOSE 8761