# Vortex CLI

[![Build Status](https://dev.azure.com/amostj/vortex-cli/_apis/build/status%2Fjordanamos.vortex-cli?branchName=main)](https://dev.azure.com/amostj/vortex-cli/_build/latest?definitionId=11&branchName=main)  [![PyPI version](https://badge.fury.io/py/vortex-cli.svg)](https://badge.fury.io/py/vortex-cli)

Vortex CLI is a command line alternative to the [Puakma Vortex IDE](https://github.com/brendonupson/PuakmaVortex) that simplifies the process of developing Puakma Applications on a [Puakma Tornado Server](https://github.com/brendonupson/Puakma) using Visual Studio Code. It allows you to clone applications from the server to a local workspace, edit the files using Visual Studio Code, and automatically upload changes to the server as you work.

Vortex CLI also comes pre-packaged with the necessary Puakma .jar files for development.

#### Visual Studio Code and Extensions

While it is possible to use without it, this software has been purposefully designed for use with [Visual Studio Code](https://github.com/microsoft/vscode) and the [Project Manager For Java](https://marketplace.visualstudio.com/items?itemName=vscjava.vscode-java-dependency) or the [Extension Pack For Java](https://marketplace.visualstudio.com/items?itemName=vscjava.vscode-java-pack) extension. This software leverages [Workspaces](https://code.visualstudio.com/docs/editor/workspaces) in Visual Studio Code and manages a `vortex.code-workspace` file within the workspace.

## Installation

1. Install the tool using pip.

   ```
   pip install vortex-cli
   ```

2. It is recommended to set the workspace you would like to work out of via the `VORTEX_HOME` environment variable.

   On Unix:

   ```
   export VORTEX_HOME=/path/to/workspace
   ```

   Otherwise, Vortex CLI will use a default **'vortex-cli-workspace'** directory inside your home directory.

3. Run vortex with the `--init` flag to create your workspace (If it doesn't already exist) and the necessary config files:
   ```
   vortex --init
   ```

4. Define the servers you will be working with in the `servers.ini` file inside the `.config` directory within your workspace. You can quickly access this using the `code` command to view your workspace in VSCode.

   ```
   vortex code
   ```

   In the `servers.ini` file, you can define as many servers as you need, each with their own unique name. For example:

   ```
   [DEFAULT] ; This section is optional and only useful if you have multiple definitions
   port = 80 ; Options provided under DEFAULT will be applied to all definitions if not provided
   soap_path = system/SOAPDesigner.pma
   default = server1 ; Useful when you have multiple definitions


   [server1] ; This can be called whatever you want and can be referenced using the '--server' flag
   host = example.com
   port = 8080 ; we can overwrite the DEFAULT value
   puakma_db_conn_id = 13
   username = myuser ; Optional - Prompted at runtime if not provided
   password = mypassword ; Optional - Prompted at runtime if not provided
   lib_path = ; additional jars that should be included in the classpath
   java_home = /usr/lib/jvm/java-17-openjdk-amd64/ ; The local path to the JRE to use. Should be the same version running on your server
   java_environment_name = JavaSE-17 ; Java Execution Environment name https://docs.osgi.org/reference/eenames.html
   ```

## Usage

For a full list of commands see `--help`.

### Command Overview

- `code`: Open the workspace in Visual Studio Code.
- `list` (or `ls`): List Puakma Applications on the server or cloned locally. (`ls` is an alias for `vortex list --local`)
- `clone`: Clone Puakma Applications and their design objects into the workspace or in the .pmx format.
- `watch`: Watch the workspace for changes to Design Objects and automatically upload them to the server.
- `clean`: Delete the locally cloned Puakma Application directories in the workspace.
- `config`: View and manage configuration.
- `log`: View the server log.
- `find`: Find Design Objects of cloned applications by name.
- `grep`: Search the contents of cloned Design Objects using a Regular Expression.
- `new`: Create new Design Objects, Applications, or Keywords. Use --update <ID> to update instead.
- `copy`: Copy a Design Object from one application to another.
- `delete`: Delete Design Objects by ID.
- `db`: Interact with Database Connections.
- `docs`: Open the Tornado Server Blackbook.
- `execute`: Execute a command on the server.
