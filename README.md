# Vortex CLI

Vortex CLI is a command line alternative to the [Puakma Vortex IDE](https://github.com/brendonupson/PuakmaVortex) that simplifies the process of developing Puakma Applications on a [Puakma Tornado Server](https://github.com/brendonupson/Puakma) using Visual Studio Code. It allows you to clone applications from the server to a local workspace, edit the files using Visual Studio Code, and automatically upload changes to the server as you work.

Vortex CLI also comes pre-packaged with the necessary Puakma .jar files for development.

## Installation

1. Install the tool using pip.

   ```
   pip install git+https://github.com/jordanamos/vortex-cli.git
   ```

2. It is recommended to set the workspace you would like to work out of via the `VORTEX_WORKSPACE` environment variable.

   ```
   export VORTEX_WORKSPACE=/path/to/workspace
   ```

   Otherwise, Vortex CLI will use a default **'vortex-cli-workspace'** directory inside your home directory.

3. Create a **vortex-server-config.ini** file in your workspace to define the server(s) you will be working with.

   To create the config file and also your workspace directory (if they don't already exist) you can use the config command:

   ```
   vortex config --init
   ```

   Then run the config command without flags to conviniently check your workspace and server configuration:

   ```
   vortex config
   ```

   Further, you can print a sample config definition using the '--sample' flag:

   ```
   vortex config --sample
   ```

   In the vortex-server-config.ini file, you can define as many servers as you need, each with their own unique name. For example:

   ```
   [DEFAULT] ; This section is optional and only useful if you have multiple definitions
   port = 80 ; Options provided under DEFAULT will be applied to all definitions if not provided
   soap_path = system/SOAPDesigner.pma
   default = server1 ; Useful when you have multiple definitions

   [server1] ; This can be called whatever you want and can be specified when using the --server flag i.e. 'vortex --server server1 list'
   host = example.com
   port = 8080 ; we can overwrite the DEFAULT value
   puakma_db_conn_id = 13
   username = myuser ; Optional
   password = mypassword ; Optional
   ```

## Usage

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
