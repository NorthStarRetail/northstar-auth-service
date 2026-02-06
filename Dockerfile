FROM maven:3.9-eclipse-temurin-21-alpine AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn package -DskipTests -B

FROM eclipse-temurin:21-jre-alpine
ENV JAVA_OPTS=""
COPY --from=build /app/target/*.jar /usr/app.jar
WORKDIR /usr/
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar /usr/app.jar"]
