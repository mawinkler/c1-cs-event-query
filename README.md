# Container Security Quick Setup Guide

- [Container Security Quick Setup Guide](#container-security-quick-setup-guide)
  - [Deployment](#deployment)
    - [Create a new policy](#create-a-new-policy)
    - [Add a cluster (w/o runtime)](#add-a-cluster-wo-runtime)
    - [Add scanner](#add-scanner)
  - [Analyze Evaluations](#analyze-evaluations)
  - [TODO](#todo)
    - [Patch deployment to local registry](#patch-deployment-to-local-registry)
  - [Support](#support)
  - [Contribute](#contribute)

## Deployment

Follow the official documentation on how to deploy container security


### Create a new policy

Don't care on the chapters *Pod properties* and *Container properties* for now - leave them as they are.

If you have requirements for *Image properties* like, you only want to allow images deployed from specific registries, configure them now. An example could be:

```txt
Log images from registries with names that do not contain intreg.trendmicro.com
```

or

```txt
Log images with tags that equal latest
```

Same applies to Scan results.

Next, you should enable all controls in `log` mode for which you can do by running the `reset_policy.py`-script. The script will reset the cluster-wide policy and all namespaced policies.


```sh
./reset_policy.py -p POLICY
```

### Add a cluster (w/o runtime)

Add a cluster following the documentation with `helm install...` and assign the previously created policy.

### Add scanner

Add a scanner following the documentation with `helm install...`.

## Analyze Evaluations

Wait at least 30 minutes, so that the continuous module of Container Security has generated the first events.

To ease your analysis, you can use the python script `query_update.py`.

I recommend to use this script on a per-namespace basis.

## TODO

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
