# Lab image pins and upstream sources

The Compose lab uses exact upstream tags and registry digests rather than moving `latest` or `stable` tags alone. These image versions are selected for the scaffold; future upgrades should update both the pin and this file.

- **OWASP Juice Shop:** `bkimminich/juice-shop:v17.1.1@sha256:9e437b456e444ff001d1663e4f6f05c796fe02f1058dd2651d6791a15b43dfeb`. The tag page identifies this as the versioned `v17.1.1` image and reports that digest as the multi-platform index digest. [Docker Hub tag details](https://hub.docker.com/layers/bkimminich/juice-shop/v17.1.1/images/sha256-f3b5b34591862b3614e072022a56b0b638cd4f667cc867318002ff2de8e875df?tab=layers) · [Official image overview](https://hub.docker.com/r/bkimminich/juice-shop)
- **DVWA:** `ghcr.io/digininja/dvwa:e8fd506@sha256:3f31c553958f57f602857f7684c8e282f7d45cc6beefe355e9975fdcc4cb3f6a`. The upstream project documents a GHCR-built image and warns against exposing DVWA to the Internet. [Official repository and Docker guidance](https://github.com/digininja/DVWA) · [GHCR version details](https://github.com/digininja/DVWA/pkgs/container/dvwa/854008121?tag=e8fd506)
- **OWASP ZAP:** `zaproxy/zap-stable:2.16.1@sha256:7840969c7c9fead565bf9734b12f49f6886db90b1d35b1f74d79710bbd081dab`. The exact `2.16.1` tag and digest are pinned. [Docker Hub tag details](https://hub.docker.com/layers/zaproxy/zap-stable/2.16.1/images/sha256-407d011ab874211e9b3a4f498cc8b9d29e344d3fea9f5bbf13dd82f22a5e5e7c) · [Official ZAP Docker guide](https://www.zaproxy.org/docs/docker/about/)

The Python and Node Dockerfiles use exact patch-level base image tags. Nmap and Nikto are installed into the scanner-runner image through the OS package manager. Compose will not publish any of these lab images to the host.
