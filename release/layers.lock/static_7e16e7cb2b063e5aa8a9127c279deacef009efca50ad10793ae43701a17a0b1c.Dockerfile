# Parent layer checksum: 778061c2b8e11b2550d4dae696decb960c312b34f4f7c0934fca9fe7a4c39817
ARG BASE_IMAGE
FROM $BASE_IMAGE
COPY . ./
RUN make static-assets

