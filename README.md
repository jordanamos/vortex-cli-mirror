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
   ```

4. Setup the [Visual Studio Code Workspace](https://code.visualstudio.com/docs/editor/workspaces) to use the same Java version as your server in /path/to/workspace/.vscode/vortex.code-workspace under "settings", for example:
   ```
   "java.configuration.runtimes": [
      {
         "default": true,
         "name": "JavaSE-1.8",
         "path": "/Library/Java/JavaVirtualMachines/temurin-8.jdk/Contents/Home"
      }
   ]
   ```

## Usage

For a full list of commands see `--help`.

<br/>

### List Puakma Applications

To list the Puakma Applications available on the server, use the `list` command:

```
vortex list
```

This will display a table showing the ID, name, template, and inheritance of each Puakma Application.

### Clone a Puakma Application

To clone a Puakma Application to the local workspace, use the `clone` command:

```
vortex clone [<APP_ID>, ...]
```

Replace `<APP_ID>` with the ID(s) of the Puakma Application(s) you want to clone. The tool will clone the application(s) into the local workspace.

### Open the workspace in Visual Studio Code

To open the Vortex CLI workspace in Visual Studio Code, use the `code` command:

```
vortex code
```

### Watch the workspace for changes

To watch the workspace containing cloned Puakma Applications and automatically upload changes to the server, use the `watch` command:

```
vortex watch
```

This will start watching the workspace for changes. As you make changes to the files in the directory, the tool will automatically upload the changes to the server.

### Delete locally cloned Puakma Applications

To delete the locally cloned Puakma Application directories in the workspace, use the `clean` command:

```
vortex clean
```

### Create Design Objects

To create new design objects, use the `new` command:

```
vortex new [NAME, ...] --app-id <app_id> --type <design_type>
```

Specify more than one name to create multiple design objects of the same type for the specified application

### Delete Design Objects

To delete a design object, use the `delete` command:

```
vortex delete [DESIGN_OBJECT_ID, ...]
```

### Find cloned Design Objects

To search for Design Objects by name use the `find` command:

```
vortex find <name> [options]
```

### Search the contents of cloned Design Objects

To search for text patterns in Design Objects using a [Regular Expression](https://learn.microsoft.com/en-us/dotnet/standard/base-types/regular-expression-language-quick-reference) use the `grep` command:

```
vortex grep <pattern> [options]
```

### Copy Design Objects from one application to another

To copy Design Objects from one application to another (You can specify many --app-ids to copy to multiple applications) use the `copy` command:

```
vortex copy DESIGN_OBJECT_ID --app-id [APP_ID ...]
```

### View the server logs

To view the last _n_ log items in the server log use the `log` command:

```
vortex log [-n LIMIT]
```
