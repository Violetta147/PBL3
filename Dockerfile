FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base
WORKDIR /app
EXPOSE 80

FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src
COPY ["First.sln", "."]
COPY ["PBL3/PBL3.csproj", "PBL3/"]
RUN dotnet restore "PBL3/PBL3.csproj"
COPY . .
WORKDIR "/src/PBL3"
RUN dotnet build "PBL3.csproj" -c Release -o /app/build
RUN dotnet publish "PBL3.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "PBL3.dll"]