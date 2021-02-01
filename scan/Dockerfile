FROM debian:buster-slim
ENV DEBIAN_VERSION buster

# initial install of av daemon
RUN echo "deb http://http.debian.net/debian/ $DEBIAN_VERSION main contrib non-free" > /etc/apt/sources.list && \
    echo "deb http://http.debian.net/debian/ $DEBIAN_VERSION-updates main contrib non-free" >> /etc/apt/sources.list && \
    echo "deb http://security.debian.org/ $DEBIAN_VERSION/updates main contrib non-free" >> /etc/apt/sources.list && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y -qq \
    clamav-daemon \
    clamav-freshclam \
    libclamunrar9 \
    ca-certificates \
    netcat-openbsd \
    wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# initial update of av databases
# get updated clamav database files 
RUN wget -O /var/lib/clamav/main.cvd http://database.clamav.net/main.cvd && \
    wget -O /var/lib/clamav/daily.cvd http://database.clamav.net/daily.cvd && \
    wget -O /var/lib/clamav/bytecode.cvd http://database.clamav.net/bytecode.cvd && \
    chown clamav:clamav /var/lib/clamav/*.cvd

# permission juggling
# change permission (chmod) and owner (chown)
RUN mkdir /var/run/clamav && \
    chown clamav:clamav /var/run/clamav && \
    chmod 750 /var/run/clamav

#Edit file clamd.conf (sed -i)
#recursively substitute all occurences of 'Foreground ***' to 'Foreground true'
RUN sed -i 's/^Foreground .*$/Foreground true/g' /etc/clamav/clamd.conf && \
    echo "TCPSocket 3310" >> /etc/clamav/clamd.conf && \

    # if ==> condition ; between then and fi ==> action if condition ok
    # write values of $HTTPProxyServer, $HTTPProxyPort, $DatabaseMirror in freshclam.conf file if they are not null
    if [ -n "$HTTPProxyServer" ]; then echo "HTTPProxyServer $HTTPProxyServer" >> /etc/clamav/freshclam.conf; fi && \
    if [ -n "$HTTPProxyPort"   ]; then echo "HTTPProxyPort $HTTPProxyPort" >> /etc/clamav/freshclam.conf; fi && \
    if [ -n "$DatabaseMirror"  ]; then echo "DatabaseMirror $DatabaseMirror" >> /etc/clamav/freshclam.conf; fi && \
    if [ -n "$DatabaseMirror"  ]; then echo "ScriptedUpdates off" >> /etc/clamav/freshclam.conf; fi && \
    #Edit file freshclam.conf (sed -i)
    #recursively substitute all occurences of 'Foreground ***' to 'Foreground true'
    sed -i 's/^Foreground .*$/Foreground true/g' /etc/clamav/freshclam.conf


# env based configs - will be called by bootstrap.sh
RUN echo "$PWD"
RUN ls

#COPY . /build-context
#WORKDIR /build-context
#RUN echo "$PWD"
#RUN ls
#CMD find .

#   ==> IF BUILD IMAGE WIH VISUAL STUDIO
#COPY scan/envconfig.sh /
#COPY scan/check.sh /
#COPY scan/bootstrap.sh /

# ==> IF BUILD IMAGE WITH POWERSHELL
COPY envconfig.sh /   
COPY check.sh /
COPY bootstrap.sh /

RUN echo "$PWD"
RUN ls

# port provision
EXPOSE 3310

# change permission (chmod) and owner (chown)
RUN chown clamav:clamav bootstrap.sh check.sh envconfig.sh /etc/clamav/clamd.conf /etc/clamav/freshclam.conf && \
    chmod u+x bootstrap.sh check.sh envconfig.sh    

# set the user and group to use to running the docker image
USER clamav:clamav

# exec
CMD ["/bootstrap.sh"]




# BUILD IMAGE .NET API ==> WORK ALONE
#
#FROM mcr.microsoft.com/dotnet/core/aspnet:3.1-buster-slim AS base
#WORKDIR /app
#EXPOSE 5003
#EXPOSE 5004
#
#FROM mcr.microsoft.com/dotnet/core/sdk:3.1-buster AS build
#WORKDIR /src
#COPY ["scan/scan.csproj", "scan/"]
#RUN dotnet restore "scan/scan.csproj"
#COPY . .
#WORKDIR "/src/scan"
#RUN dotnet build "scan.csproj" -c Release -o /app/build
#
#FROM build AS publish
#RUN dotnet publish "scan.csproj" -c Release -o /app/publish
#
#FROM base AS final
#WORKDIR /app
#COPY --from=publish /app/publish .
#ENTRYPOINT ["dotnet", "scan.dll", "scan/bootstrap.sh"]