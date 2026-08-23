# Build stage
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Copy project files and restore dependencies
COPY Valkyrie/Valkyrie.slnx ./
COPY Valkyrie/Valkyrie/Valkyrie.csproj ./Valkyrie/
COPY Valkyrie/Valkyrie.Tests/Valkyrie.Tests.csproj ./Valkyrie.Tests/
RUN dotnet restore Valkyrie/Valkyrie.csproj

# Copy the rest of the source code and build
COPY Valkyrie/ ./
RUN dotnet publish Valkyrie/Valkyrie.csproj -c Release -o /app/publish --no-restore

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /app/publish ./

# Expose HTTP port
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080
ENV ASPNETCORE_ENVIRONMENT=Production

ENTRYPOINT ["dotnet", "Valkyrie.dll"]
