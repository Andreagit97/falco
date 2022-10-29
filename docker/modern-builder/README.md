# Modern-builder image

## Description

This image will be used by our CI jobs to generate artifacts (tar, deb, rpm) and docker images for Falco with the modern BPF probe.

## Build modern-builder image locally

From the project root:

```bash
docker build --tag falco-modern-builder:latest - < ./docker/modern-builder/Dockerfile
```
