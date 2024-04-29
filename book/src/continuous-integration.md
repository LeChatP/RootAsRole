# What does Continuous Integration mean?

Continuous Integration (CI) is a software development practice where developers regularly merge their code changes into a central repository, after which automated builds and tests are run. The key goals of CI are to find and address bugs quicker, improve software quality, and reduce the time it takes to validate and release new software updates.

## What is implemented in RootAsRole?

In RootAsRole, we use GitHub Actions to automate the CI process. We have defined a workflow that runs on every push to the `main` branch. This workflow consists of testing the code, building the project.
