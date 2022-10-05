


# Template Repo for Experiments

This repo can be used as a template when you would like to perform "informal" code
experiments and explorations.

## Adapting and Using the Template:
The main code of your experiments should go into the [`./src`](./src) directory.
This can happen either as a python package or as individual python scripts -
whatever seems more appropriate.

You may use the the [`./tests`](./tests) directory for describing any tests and
the [`./example_data`](./example_data) directory for storing any example data your
code might need.

Please add your dependencies to the [`./requirements.txt`](./requirements.txt).

Please remove or add service dependencies in the
[`./.devcontainer/docker-compose.yml`](./.devcontainer/docker-compose.yml) as needed.

Please remember, in exploration or experiment tasks, it's not expected to present a
very polished and elegant implementation but only to find out the principle solution
to a problem. So it is fine here to cut some corners and leave some rough edges in the
code base as long as it doesn't impact the underlying architecture of the solution.

Please use the following section to document your experiments and your findings:

## Documentation:

Please A longer description of your experiments and findings can go here.

## Quick Start
For setting up the development environment, we rely on the
[devcontainer feature](https://code.visualstudio.com/docs/remote/containers) of vscode
in combination with Docker Compose.

To use it, you have to have Docker Compose as well as vscode with its "Remote - Containers" extension (`ms-vscode-remote.remote-containers`) installed.
Then open this repository in vscode and run the command
`Remote-Containers: Reopen in Container` from the vscode "Command Palette".

This will give you a full-fledged, pre-configured development environment including:
- infrastructural dependencies (databases, etc.)
- all relevant vscode extensions pre-installed
- pre-configured linting and auto-formating
- a pre-configured debugger
- automatic license-header insertion

If you prefer not to use vscode, you could get a similar setup (without the editor specific features)
by running the following commands:
``` bash
# Execute in the repo's root dir:
cd ./.devcontainer

# build and run the environment with docker-compose
docker-compose up

# attach to the main container:
# (you can open multiple shell sessions like this)
docker exec -it devcontainer_app_1 /bin/bash
```

## License
This repository is free to use and modify according to the [Apache 2.0 License](./LICENSE).
