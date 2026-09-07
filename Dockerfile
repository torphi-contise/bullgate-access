# syntax=docker/dockerfile:1.7

ARG DOTNET_SDK_IMAGE=mcr.microsoft.com/dotnet/sdk:10.0.400
ARG DOTNET_ASPNET_IMAGE=mcr.microsoft.com/dotnet/aspnet:10.0

FROM ${DOTNET_SDK_IMAGE} AS publish
WORKDIR /src

COPY global.json NuGet.Config Directory.Build.props Directory.Packages.props ./
COPY src/Bullgate.Access.Domain/Bullgate.Access.Domain.csproj src/Bullgate.Access.Domain/
COPY src/Bullgate.Access.Application/Bullgate.Access.Application.csproj src/Bullgate.Access.Application/
COPY src/Bullgate.Access.Infrastructure/Bullgate.Access.Infrastructure.csproj src/Bullgate.Access.Infrastructure/
COPY src/Bullgate.Access.Api/Bullgate.Access.Api.csproj src/Bullgate.Access.Api/

RUN dotnet restore src/Bullgate.Access.Api/Bullgate.Access.Api.csproj

COPY src/Bullgate.Access.Domain/ src/Bullgate.Access.Domain/
COPY src/Bullgate.Access.Application/ src/Bullgate.Access.Application/
COPY src/Bullgate.Access.Infrastructure/ src/Bullgate.Access.Infrastructure/
COPY src/Bullgate.Access.Api/ src/Bullgate.Access.Api/

RUN dotnet publish src/Bullgate.Access.Api/Bullgate.Access.Api.csproj \
    --configuration Release \
    --no-restore \
    --self-contained false \
    -p:UseAppHost=false \
    --output /app/publish \
    && rm -f /app/publish/appsettings.Development.json

FROM ${DOTNET_ASPNET_IMAGE} AS final
WORKDIR /app

ENV ASPNETCORE_ENVIRONMENT=Production \
    ASPNETCORE_HTTP_PORTS=8080 \
    DOTNET_EnableDiagnostics=0

EXPOSE 8080

COPY --from=publish /app/publish/ ./
COPY scripts/compose-api-entrypoint.sh /usr/local/bin/bullgate-access-api

RUN apt-get update \
    && apt-get install -y --no-install-recommends libgssapi-krb5-2 \
    && rm -rf /var/lib/apt/lists/* \
    && chmod 0755 /usr/local/bin/bullgate-access-api \
    && mkdir -p /home/app/.aspnet/DataProtection-Keys \
    && chown -R $APP_UID:$APP_UID /home/app

USER $APP_UID

ENTRYPOINT ["/usr/local/bin/bullgate-access-api"]
