# Parent layer checksum: 246d7eef3c85dfaba9ae31ffb25d5e52a864121c527907337bd6e5688a49b7aa
ARG BASE_IMAGE
FROM $BASE_IMAGE
COPY . ./
RUN cd ui && yarn run build

