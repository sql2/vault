# Parent layer checksum: 25e9840bf289aaf9dd6e86ac9c7be90009517f66cbc9efbb385ed676efef9ed9
ARG BASE_IMAGE
FROM $BASE_IMAGE
COPY . ./
RUN cd ui && yarn install
RUN cd ui && npm rebuild node-sass

