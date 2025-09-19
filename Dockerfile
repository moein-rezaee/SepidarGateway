# Build stage
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

COPY SepidarGateway/SepidarGateway.csproj SepidarGateway/
RUN dotnet restore SepidarGateway/SepidarGateway.csproj

COPY SepidarGateway/ SepidarGateway/
RUN dotnet publish SepidarGateway/SepidarGateway.csproj -c Release -o /app/publish

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:9.0-alpine AS final
WORKDIR /app

COPY --from=build /app/publish ./
EXPOSE 5259

ENV ASPNETCORE_URLS=http://+:5259
ENTRYPOINT ["dotnet", "SepidarGateway.dll"]
