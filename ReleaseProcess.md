# Introduction

This document contains the release process which should be followed when generating a new release of the IBM Security Verify Access operator.

## Version Number

The version number should be of the format: `v<year>.<month>.0`, for example: `v23.03.0`.


# Generating a GitHub Release

In order to generate a new version of the operator a new GitHub release should be created: [https://github.com/IBM-Security/verify-access-operator/releases/new](https://github.com/IBM-Security/verify-access-operator/releases/new). 

The fields for the release should be:

|Field|Description
|-----|----------- 
|Tag | The version number, e.g. `v23.03.0`
|Release title | The version number, e.g. `v23.03.0`
|Release description | The resources associated with the \<version\-number> IBM Security Verify Access operator release.

After the release has been created the GitHub actions workflow ([https://github.com/IBM-Security/verify-access-operator/actions/workflows/build.yml](https://github.com/IBM-Security/verify-access-operator/actions/workflows/build.yml)) will be executed to generate the build.  This build process will include:

* publishing the generated docker images to DockerHub;
* adding the manifest zip and bundle.yaml files to the release artifacts in GitHub.

# Publishing to OperatorHub.io

Once a new GitHub release has been generated the updated operator bundle needs to be published to OperatorHub.io.  Information on how to do this can be found at the following URL: [https://k8s-operatorhub.github.io/community-operators/](https://k8s-operatorhub.github.io/community-operators/).

At a high level you need to (taken from: [https://k8s-operatorhub.github.io/community-operators/contributing-via-pr/]()):

1. Test the operator locally.
2. Fork the [GitHub project](https://github.com/k8s-operatorhub/community-operators).
3. Add the operator bundle to the verify-access-operator directory.
4. Push a 'signed' commit of the changes.  See [https://k8s-operatorhub.github.io/community-operators/contributing-prerequisites/](https://k8s-operatorhub.github.io/community-operators/contributing-prerequisites/).  The easiest way to sign the commit is to use the `git commit -s -m '<description>'` command to commit the changes.
5. Contribute the changes back to the main GitHub repository (using the 'Contribute' button in the GitHub console).  This will have the effect of creating a new pull request against the main GitHub repository.
6. Monitor the 'checks' against the pull request to ensure that all of the automated test cases pass.
7. Wait for the pull request to be merged.  This will usually happen overnight.

# Publishing to OpenShift Community Catalog

Once a new GitHub release has been generated the updated operator bundle needs to be published to the OpenShift community operator catalog.  Information on how to do this can be found at the following URL: [https://k8s-operatorhub.github.io/community-operators/](https://k8s-operatorhub.github.io/community-operators/).

At a high level you need to (taken from: [https://k8s-operatorhub.github.io/community-operators/contributing-via-pr/]()):

1. Test the operator locally.
2. Fork the [GitHub project](https://github.com/redhat-openshift-ecosystem/community-operators-prod).
3. Add the operator bundle to the verify-access-operator directory.
4. Push a 'signed' commit of the changes.  See [https://k8s-operatorhub.github.io/community-operators/contributing-prerequisites/](https://k8s-operatorhub.github.io/community-operators/contributing-prerequisites/).  The easiest way to sign the commit is to use the `git commit -s -m '<description>'` command to commit the changes.
5. Contribute the changes back to the main GitHub repository (using the 'Contribute' button in the GitHub console).  This will have the effect of creating a new pull request against the main GitHub repository.
6. Monitor the 'checks' against the pull request to ensure that all of the automated test cases pass.
7. Wait for the pull request to be merged.  This will usually happen overnight.

