# Falco development image

This docker image can be easily generated starting from a clean Falco build.

## 1. Clone the Falco repo ⬇️

```bash
git clone https://github.com/falcosecurity/falco.git
```

## 2. Prepare the build directory 🏗️

Starting from the project root:

```bash
mkdir build && cd build
cmake -DUSE_BUNDLED_DEPS=On -DCREATE_TEST_TARGETS=Off -DCPACK_GENERATOR=TGZ ..
make dev-docker
```
> __Please note__: These cmake options `-DUSE_BUNDLED_DEPS=On -DCREATE_TEST_TARGETS=Off -DCPACK_GENERATOR=TGZ` are the required ones but you can provide additionals option to build the image according to your needs (for example you can pass `-DMINIMAL_BUILD=On` if you want a minimal build image)

## 3. Run the docker image locally 🏎️

```bash
docker run --rm -i -t --privileged falco-dev
```
> __Please note__ ⚠️: If you face some errors regarding the glibc version is possible that your local machine has a too old or too recent `GLIBC` version ("/usr/bin/falco: /lib/x86_64-linux-gnu/libc.so.6: version GLIBC_2.34 not found (required by /usr/bin/falco)"). In this case you have to change the `runner` image: `FROM ubuntu:22.04 AS runner`, instead of `ubuntu:22.04` you can use an image with the needed `glic` version

If you change something in the Falco source code you can simply rebuild the image with:

```bash
make dev-docker
```
