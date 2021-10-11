# Introduction

This document contains the release process which should be followed when generating a new release of the IBM Security Verify Access operator.

## Version Number

The version number should be of the format: `v<year>.<month>.0`, for example: `v21.10.0`.


# Generating a GitHub Release

In order to generate a new version of the operator a new GitHub release should be created: [https://github.com/IBM-Security/verify-access-operator/releases/new](https://github.com/IBM-Security/verify-access-operator/releases/new). 

The fields for the release should be:

|Field|Description
|-----|----------- 
|Tag | The version number, e.g. `v21.10.0`
|Release title | The version number, e.g. `v21.10.0`
|Release description | The resources associated with the \<version\-number> IBM Security Verify Access operator release.

After the release has been created the GitHub actions workflow ([https://github.com/IBM-Security/verify-access-operator/actions/workflows/build.yml](https://github.com/IBM-Security/verify-access-operator/actions/workflows/build.yml)) will be executed to generate the build.  This build process will include:

* publishing the generated docker images to DockerHub;
* adding the manifest zip and bundle.yaml files to the release artifacts in GitHub.

# Publishing to OperatorHub.io

Once a new GitHub release has been generated the updated operator bundle needs to be published to OperatorHub.io.  Information on how to do this can be found at the following URL: [https://k8s-operatorhub.github.io/community-operators/](https://k8s-operatorhub.github.io/community-operators/).

At a high level you need to (taken from: [https://k8s-operatorhub.github.io/community-operators/contributing-via-pr/]()):

1. Test the operator locally
2. Fork the [GitHub project](https://github.com/operator-framework/community-operators)
4. Place the operator in the target directory ([more info](https://k8s-operatorhub.github.io/community-operators/contributing-where-to/])): 
	- community-operators (Openshift operator) 
	- upstream-community-operators (Kubernetes operator)
5. Configure ci.yaml file ([more info](https://k8s-operatorhub.github.io/community-operators/operator-ci-yaml/))
	- Setup reviewers
	- Operator versioning strategy
3. Make a pull request
	- You must ensure that the comment for the commit contains a signature. See [https://k8s-operatorhub.github.io/community-operators/contributing-prerequisites/](https://k8s-operatorhub.github.io/community-operators/contributing-prerequisites/) 
8. Verify tests and fix problems, if possible
9. Ask for help in the PR in case of problems


