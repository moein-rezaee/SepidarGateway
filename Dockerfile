# Build stage
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

COPY SepidarGateway.sln ./
COPY SepidarGateway/SepidarGateway.csproj SepidarGateway/
COPY SepidarGateway.Tests/SepidarGateway.Tests.csproj SepidarGateway.Tests/
RUN dotnet restore SepidarGateway.sln

COPY . ./
RUN dotnet publish SepidarGateway/SepidarGateway.csproj -c Release -o /app/publish

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:9.0-alpine AS final
WORKDIR /app

COPY --from=build /app/publish ./
EXPOSE 5000

ENV ASPNETCORE_URLS=http://+:5000
ENTRYPOINT ["dotnet", "SepidarGateway.dll"]
