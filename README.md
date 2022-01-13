# Container Security Quick Setup Guide

- [Container Security Quick Setup Guide](#container-security-quick-setup-guide)
  - [Requirements](#requirements)
  - [Setup Cloud One API Endpoint](#setup-cloud-one-api-endpoint)
  - [Run Environment: Docker](#run-environment-docker)
    - [Build](#build)
    - [Run](#run)
  - [Usage - Analyze Evaluations](#usage---analyze-evaluations)
  - [Planned functionality](#planned-functionality)
    - [Patch deployment to local registry](#patch-deployment-to-local-registry)
  - [Support](#support)
  - [Contribute](#contribute)

## Requirements

- Running and configured Cloud One Container Security instance
- Cloud One Api Key with full access

## Setup Cloud One API Endpoint

Locally, on your system create the following two files:

`/etc/cloudone-credentials/api_key`

containing your Cloud One API Key

`1wxxxxxxxxxxxxxxxxxxxxxxxxx:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`

and

`/etc/cloudone-credentials/c1_url`

pointing to your Cloud One API endpoint, e.g.

`us-1.cloudone.trendmicro.com:443`

## Run Environment: Docker

### Build

```sh
docker build -t c1cs-query-update .
```

### Run

```sh
docker run --rm \
  -v /etc/cloudone-credentials:/etc/cloudone-credentials:ro \
  c1cs-query-update -c CLUSTER_NAME -p POLICY_NAME ...
```

> If you don't want to build the image yourself just use the image name `mawinkler/c1cs-query-update`.
## Usage - Analyze Evaluations

Wait at least 30 minutes, so that the continuous module of Container Security has generated the first events.

I recommend to use this tool on a per-namespace basis, like this:

```sh
docker run --rm \
  -v /etc/cloudone-credentials:/etc/cloudone-credentials:ro \
  c1cs-query-update -c playground_gke -p relaxed_playground_gke -n falco
```

This will return you something like this:

```sh
2022-01-13 16:41:06 INFO (MainThread) [<module>] Collecting evaluation event reasons
2022-01-13 16:41:06 INFO (MainThread) [collect_reasons] Start time: 2022-01-13T15:41:06Z
2022-01-13 16:41:06 INFO (MainThread) [collect_reasons] End time: 2022-01-13T16:41:06Z
2022-01-13 16:41:09 INFO (MainThread) [collect_reasons] Number of filtered reasons: 30
2022-01-13 16:41:09 INFO (MainThread) [extract_images] Number of violating images: 30
2022-01-13 16:41:09 INFO (MainThread) [print_tables] 
Event Type: REGISTRY, Event Count: 27
+-------------+--------------------------------------------------------+-------------------------------------+---------------------------+------------+
| namespace   | pod                                                    | image                               | container                 | rule       |
+-------------+--------------------------------------------------------+-------------------------------------+---------------------------+------------+
| prometheus  | alertmanager-prometheus-kube-prometheus-alertmanager-0 | alertmanager                        | alertmanager              | not-equals |
| prometheus  | alertmanager-prometheus-kube-prometheus-alertmanager-0 | prometheus-config-reloader          | config-reloader           | not-equals |
| kube-system | event-exporter-gke-5479fd58c8-pq8nw                    | event-exporter                      | event-exporter            | not-equals |
| kube-system | event-exporter-gke-5479fd58c8-pq8nw                    | prometheus-to-sd                    | prometheus-to-sd-exporter | not-equals |
| falco       | falco-exporter-h7m8x                                   | falco-exporter                      | falco-exporter            | not-equals |
| falco       | falco-falcosidekick-797d4c5d8-ns45j                    | falcosidekick                       | falcosidekick             | not-equals |
| falco       | falco-falcosidekick-ui-67749c4fb5-s5hhn                | falcosidekick-ui                    | falcosidekick             | not-equals |
| kube-system | fluentbit-gke-7wx4l                                    | fluent-bit                          | fluentbit                 | not-equals |
| kube-system | fluentbit-gke-7wx4l                                    | fluent-bit-gke-exporter             | fluentbit-gke             | not-equals |
| kube-system | gke-metrics-agent-pxkrr                                | gke-metrics-agent                   | gke-metrics-agent         | not-equals |
| kube-system | konnectivity-agent-9868c489c-tsxk6                     | proxy-agent                         | konnectivity-agent        | not-equals |
| kube-system | konnectivity-agent-autoscaler-698b6d8768-4mjl6         | cluster-proportional-autoscaler     | autoscaler                | not-equals |
| kube-system | kube-dns-697dc8fc8b-n2598                              | k8s-dns-kube-dns                    | kubedns                   | not-equals |
| kube-system | kube-dns-697dc8fc8b-n2598                              | k8s-dns-dnsmasq-nanny               | dnsmasq                   | not-equals |
| kube-system | kube-dns-697dc8fc8b-n2598                              | k8s-dns-sidecar                     | sidecar                   | not-equals |
| kube-system | kube-dns-697dc8fc8b-n2598                              | prometheus-to-sd                    | prometheus-to-sd          | not-equals |
| kube-system | l7-default-backend-7db896cb4-z2dg5                     | ingress-gce-404-server-with-metrics | default-http-backend      | not-equals |
| kube-system | metrics-server-v0.4.4-857776bc9c-9snww                 | metrics-server                      | metrics-server            | not-equals |
| kube-system | metrics-server-v0.4.4-857776bc9c-9snww                 | addon-resizer                       | metrics-server-nanny      | not-equals |
| nginx       | nginx-6799fc88d8-dvg2w                                 | nginx                               | nginx                     | not-equals |
| kube-system | pdcsi-node-5mlqf                                       | csi-node-driver-registrar           | csi-driver-registrar      | not-equals |
| prometheus  | prometheus-grafana-6ccf94f848-26nn8                    | k8s-sidecar                         | grafana-sc-dashboard      | not-equals |
| prometheus  | prometheus-grafana-6ccf94f848-26nn8                    | grafana                             | grafana                   | not-equals |
| prometheus  | prometheus-kube-prometheus-operator-57ddd6fcfb-bmtnl   | prometheus-operator                 | kube-prometheus-stack     | not-equals |
| prometheus  | prometheus-kube-state-metrics-79f9cf87df-vlbqr         | kube-state-metrics                  | kube-state-metrics        | not-equals |
| prometheus  | prometheus-prometheus-kube-prometheus-prometheus-0     | prometheus                          | prometheus                | not-equals |
| prometheus  | prometheus-prometheus-node-exporter-5k69x              | node-exporter                       | node-exporter             | not-equals |
+-------------+--------------------------------------------------------+-------------------------------------+---------------------------+------------+
2022-01-13 16:41:09 INFO (MainThread) [print_tables] 
Event Type: CONTAINERSECURITYCONTEXT, Event Count: 3
+-------------+------------------------------------------------------+----------------------------------------+---------------+------------+
| namespace   | pod                                                  | image                                  | container     | rule       |
+-------------+------------------------------------------------------+----------------------------------------+---------------+------------+
| falco       | falco-4x7b8                                          | falco                                  | falco         | privileged |
| kube-system | kube-proxy-gke-playground-default-pool-fa5fe362-clp6 | kube-proxy-amd64                       | kube-proxy    | privileged |
| kube-system | pdcsi-node-5mlqf                                     | gcp-compute-persistent-disk-csi-driver | gce-pd-driver | privileged |
+-------------+------------------------------------------------------+----------------------------------------+---------------+------------+
2022-01-13 16:41:09 INFO (MainThread) [<module>] Done
```

You will get potentially multiple tables, each introduced by a discoverd `Event Type` like `UNSCANNEDIMAGE`, `REGISTRY` or `CONTAINERSECURITYCONTEXT`

Within the table the policy violating image is shown. Verify this and if you want to set image-based exceptions rerun the script with one of the two update flags `-un` or `-uc`.

The `-un` modifies the cluster policy to a namespaced policy (if it wasn't before) and creates a namespaced policy with the same settings as the cluster-wide policy, but set's exceptions for the images identifies during the analysis.

`-uc` effectively does the same, but directly modifies the cluster-wide policy. In both variants, existing exceptions will not be overwritten.

```sh
docker run --rm \
  -v /etc/cloudone-credentials:/etc/cloudone-credentials:ro \
  c1cs-query-update -c playground_gke -p relaxed_playground_gke -n kube-system -un
```

```sh
2022-01-13 16:41:40 INFO (MainThread) [<module>] Collecting evaluation event reasons
2022-01-13 16:41:40 INFO (MainThread) [collect_reasons] Start time: 2022-01-13T15:41:40Z
2022-01-13 16:41:40 INFO (MainThread) [collect_reasons] End time: 2022-01-13T16:41:40Z
2022-01-13 16:41:43 INFO (MainThread) [collect_reasons] Number of filtered reasons: 17
2022-01-13 16:41:43 INFO (MainThread) [extract_images] Number of violating images: 17
2022-01-13 16:41:44 INFO (MainThread) [pull_policy] Total number of policies: 2
2022-01-13 16:41:44 INFO (MainThread) [policy_add_exceptions] Updating namespaced policy
2022-01-13 16:41:44 INFO (MainThread) [policy_add_exceptions] Adding image exception for event-exporter
2022-01-13 16:41:44 INFO (MainThread) [policy_add_exceptions] Adding image exception for prometheus-to-sd
2022-01-13 16:41:44 INFO (MainThread) [policy_add_exceptions] Adding image exception for fluent-bit
2022-01-13 16:41:44 INFO (MainThread) [policy_add_exceptions] Adding image exception for fluent-bit-gke-exporter
2022-01-13 16:41:44 INFO (MainThread) [policy_add_exceptions] Adding image exception for gke-metrics-agent
2022-01-13 16:41:44 INFO (MainThread) [policy_add_exceptions] Adding image exception for proxy-agent
2022-01-13 16:41:44 INFO (MainThread) [policy_add_exceptions] Adding image exception for cluster-proportional-autoscaler
2022-01-13 16:41:44 INFO (MainThread) [policy_add_exceptions] Adding image exception for k8s-dns-kube-dns
2022-01-13 16:41:44 INFO (MainThread) [policy_add_exceptions] Adding image exception for k8s-dns-dnsmasq-nanny
2022-01-13 16:41:44 INFO (MainThread) [policy_add_exceptions] Adding image exception for k8s-dns-sidecar
2022-01-13 16:41:44 INFO (MainThread) [policy_add_exceptions] Adding image exception for prometheus-to-sd
2022-01-13 16:41:44 INFO (MainThread) [policy_add_exceptions] Adding image exception for ingress-gce-404-server-with-metrics
2022-01-13 16:41:44 INFO (MainThread) [policy_add_exceptions] Adding image exception for metrics-server
2022-01-13 16:41:44 INFO (MainThread) [policy_add_exceptions] Adding image exception for addon-resizer
2022-01-13 16:41:44 INFO (MainThread) [policy_add_exceptions] Adding image exception for csi-node-driver-registrar
2022-01-13 16:41:44 INFO (MainThread) [policy_add_exceptions] Adding image exception for kube-proxy-amd64
2022-01-13 16:41:44 INFO (MainThread) [policy_add_exceptions] Adding image exception for gcp-compute-persistent-disk-csi-driver
2022-01-13 16:41:44 INFO (MainThread) [<module>] Updating policy
2022-01-13 16:41:44 INFO (MainThread) [print_tables] 
```

Container Security Continuous should now ignore policy violations in the given namespace.

## Planned functionality

### Patch deployment to local registry

- describe deployment
- pull image
- push to local registry
- patch
- delete deployment
- apply patched deployment

The reason for the above is pretty simple. If you would set `Block images that are not scanned`, very likely your cluster would break pretty soon. So here are my best practices on how to set up a policy without breaking the cluster.

1. Start in log-only mode
2. Configure two of the top prio policies `Trusted Repo` and `Prohibit Privileged Mode`
3. Analyze the events after running the deployed cluster for a while
   1. Evaluate the Events and see, what would have been blocked
4. Based on the events, develop namespaced policies, namespace exclusions and adaptions to the policy

## Support

This is an Open Source community project. Project contributors may be able to help, depending on their time and availability. Please be specific about what you're trying to do, your system, and steps to reproduce the problem.

For bug reports or feature requests, please [open an issue](../../issues). You are welcome to [contribute](#contribute).

Official support from Trend Micro is not available. Individual contributors may be Trend Micro employees, but are not official support.

## Contribute

I do accept contributions from the community. To submit changes:

1. Fork this repository.
1. Create a new feature branch.
1. Make your changes.
1. Submit a pull request with an explanation of your changes or additions.

I will review and work with you to release the code.
