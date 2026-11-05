# Internal lab

The default lab comprises the pinned OWASP Juice Shop and DVWA targets plus ZAP and the scanner-runner. Compose attaches all of them to `lab_net`, whose `internal: true` setting prevents direct Internet routing. The backend is also attached to that network so a later approved orchestration layer can reach lab services. No lab target, ZAP API, or runner port is published to the host.

No optional Metasploitable2 image is configured. Prompt 1 notes that there is no official image; use a separately reviewed VM or omit it.

A Docker-capable host must verify runtime isolation after `make up`. This sandbox does not have a Docker daemon, so this repository's static checks do not claim that the lab has been started or that its egress-denial behavior has been observed.
