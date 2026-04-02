FROM maven:3.9.6-eclipse-temurin-17 AS builder
WORKDIR /app
COPY pom.xml .
# Cache dependencies
RUN mvn dependency:go-offline -q
COPY src ./src
RUN mvn package -q -DskipTests

# Runtime image
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app

RUN mkdir -p logs

COPY --from=builder /app/target/virustotal-bot-1.0.0.jar app.jar

# Create non-root user
RUN addgroup -S vtbot && adduser -S vtbot -G vtbot
RUN chown -R vtbot:vtbot /app
USER vtbot

CMD ["java", "-jar", "app.jar"]
