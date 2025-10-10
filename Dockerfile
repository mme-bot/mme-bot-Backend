# syntax=docker/dockerfile:1

FROM eclipse-temurin:25-jdk AS builder
WORKDIR /workspace

COPY gradlew gradlew
COPY gradlew.bat gradlew.bat
COPY gradle gradle
COPY build.gradle* settings.gradle* ./
RUN chmod +x gradlew

COPY src/ src/


RUN ./gradlew clean bootJar --no-daemon \
    && JAR_FILE=$(ls build/libs | grep '\.jar$' | grep -v 'plain' | head -n 1) \
    && echo $JAR_FILE \
    && mv build/libs/$JAR_FILE app.jar

FROM eclipse-temurin:25-jdk
ARG APP_PORT=8000
ENV SERVER_PORT=${APP_PORT}
WORKDIR /app

COPY --from=builder /workspace/app.jar app.jar

EXPOSE 8000

ENTRYPOINT ["java", "-jar", "/app/app.jar"]
