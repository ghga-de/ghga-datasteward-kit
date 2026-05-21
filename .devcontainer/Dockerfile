FROM mcr.microsoft.com/devcontainers/python:3.0.6-3.13-trixie

ENV PYTHONUNBUFFERED=1

# Update and upgrade system packages for latest security fixes
RUN apt-get update && apt-get upgrade -y

RUN apt-get install -y --no-install-recommends \
  # add some CLI tools for developers and AI agents
  ripgrep fd-find bat \
  && rm -rf /var/lib/apt/lists/* \
  # Debian installs fd and bat under fdfind/batcat; add canonical short names
  && ln -sf /usr/bin/fdfind /usr/local/bin/fd \
  && ln -sf /usr/bin/batcat /usr/local/bin/bat

# Update args in docker-compose.yaml to set the UID/GID of the "vscode" user.
ARG USER_UID=1000
ARG USER_GID=$USER_UID
RUN if [ "$USER_GID" != "1000" ] || [ "$USER_UID" != "1000" ]; then groupmod --gid $USER_GID vscode && usermod --uid $USER_UID --gid $USER_GID vscode; fi

# [Option] Install Node.js
ARG INSTALL_NODE="false"
ARG NODE_VERSION="lts/*"
RUN if [ "${INSTALL_NODE}" = "true" ]; then su vscode -c "umask 0002 && . /usr/local/share/nvm/nvm.sh && nvm install ${NODE_VERSION} 2>&1"; fi

# Copy install and launcher script to bin:
COPY ./dev_install /bin
COPY ./dev_launcher /bin

CMD ["sleep", "infinity"]
