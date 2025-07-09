# Forzar build en AMD64 si corres en M1/M2
FROM --platform=linux/amd64 python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV CGO_ENABLED=1

# Instalar dependencias base
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        g++ \
        git \
        wget \
        curl \
        pkg-config \
        libcairo2 \
        libcairo2-dev \
        libpango1.0-0 \
        libpango1.0-dev \
        libpangocairo-1.0-0 \
        libpangoft2-1.0-0 \
        libffi-dev \
        libgdk-pixbuf2.0-0 \
        libgdk-pixbuf2.0-dev \
        libxml2 \
        libxslt1.1 \
        libglib2.0-0 \
        libglib2.0-dev \
        fonts-liberation \
        fonts-dejavu \
        libjpeg-dev \
        zlib1g-dev \
        shared-mime-info \
        unzip \
    && rm -rf /var/lib/apt/lists/*

# Instalar Go 1.24.2
RUN wget https://go.dev/dl/go1.24.2.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.24.2.linux-amd64.tar.gz && \
    rm go1.24.2.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

# Instalar Python tools
RUN pip install wfuzz wafw00f

# Config Git para evitar SSH prompts
RUN git config --global url."https://github.com/".insteadOf git@github.com: && \
    git config --global url."https://".insteadOf git://

# Instalar Go tools
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/tomnomnom/assetfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/tomnomnom/qsreplace@latest && \
    go install github.com/tomnomnom/gf@latest && \
    go install -tags javascript,markdown github.com/projectdiscovery/katana/cmd/katana@latest


# Move Go binaries to /usr/local/bin
RUN cp -r /root/go/bin/* /usr/local/bin/

# GF patterns
RUN git clone https://github.com/1ndianl33t/Gf-Patterns.git /tmp/Gf-Patterns && \
    mkdir -p /root/.gf && \
    cp /tmp/Gf-Patterns/*.json /root/.gf/ && \
    rm -rf /tmp/Gf-Patterns

# Dalfox
RUN go install github.com/hahwul/dalfox/v2@latest && \
    cp /root/go/bin/dalfox /usr/local/bin/

# FFUF
RUN go install github.com/ffuf/ffuf/v2@latest && \
    cp /root/go/bin/ffuf /usr/local/bin/

# SQLMAP
RUN git clone https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap && \
    ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap

# XSStrike
RUN git clone https://github.com/s0md3v/XSStrike.git /opt/XSStrike && \
    ln -s /opt/XSStrike/xsstrike.py /usr/local/bin/xsstrike

# tplmap
RUN git clone https://github.com/epinna/tplmap.git /opt/tplmap && \
    ln -s /opt/tplmap/tplmap.py /usr/local/bin/tplmap

# SecLists
RUN git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists

# Make all .py tools executable
RUN chmod +x /usr/local/bin/sqlmap \
    /usr/local/bin/xsstrike \
    /usr/local/bin/tplmap


# XSStrike
RUN rm -rf /usr/share/XSStrike && \
    git clone https://github.com/s0md3v/XSStrike.git /usr/share/XSStrike && \
    pip install --no-cache-dir -r /usr/share/XSStrike/requirements.txt && \
    rm -f /usr/local/bin/xsstrike && \
    ln -s /usr/share/XSStrike/xsstrike.py /usr/local/bin/xsstrike && \
    chmod +x /usr/local/bin/xsstrike

# Instalar Nuclei
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    cp /root/go/bin/nuclei /usr/local/bin/


# Descargar templates
ENV NUCLEI_TEMPLATES=/root/nuclei-templates
RUN nuclei -update
RUN nuclei


# Copiar requirements.txt primero
COPY requirements.txt /tmp/

# Instalar dependencias Python
RUN pip install --no-cache-dir -r /tmp/requirements.txt


# Copiar app
WORKDIR /app
COPY . /app

RUN python3 backend/init_db.py


EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--reload"]





