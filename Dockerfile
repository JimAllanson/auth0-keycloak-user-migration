FROM gradle:6.2.0-jdk8 as build

WORKDIR /build
COPY . .
RUN gradle jar

FROM jboss/keycloak:11.0.0
COPY --from=build /build/build/libs/user-migration-0.1.0.jar /opt/jboss/keycloak/standalone/deployments/user-migration.jar