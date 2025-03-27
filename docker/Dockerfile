FROM continuumio/anaconda3

RUN apt-get update && \
    apt-get install -y curl gnupg && \
    curl -sL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y nodejs

# Verify installation (optional)
RUN node -v
RUN npm -v
