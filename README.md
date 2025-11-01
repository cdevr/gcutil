# gcutil - Google Cloud VM CLI Tool

A command-line tool built with Cobra for managing Google Cloud VM instances. Mostly written with Claude Code as an experiment for AI assisted software development.

## Features

- OAuth2 web-based authentication
- List all VMs across all zones in a Google Cloud project
- SSH and SCP operations on your Cloud VMs
- Clean tabular output with instance details

## Prerequisites

1. Go 1.25.1 or later
2. A Google Cloud Project with Compute Engine API enabled

## Installation

```bash
go install .
```

## Usage

### Available Commands

- `auth` - Authenticate with Google Cloud
- `list` - List all VMs in Google Cloud projects
- `ssh` - SSH to a Google Cloud VM instance
- `scp` - SCP to/from a Google Cloud VM instance
- `addkey` - Add user with SSH key to a Google cloud instance
- `completion` - Generate autocompletion script for your shell
- `help` - Help about any command

### Authenticate

Note: Authentication is not necessary. If you are not authenticated or the token needs refreshing, a URL to authenticate will be printed on the CLI. You can click on the link in most terminal emulators, or copy it into your web browser and use it that way.

```bash
./gcutil auth
```

The token is saved to `token.json`.

### List VMs

```bash
./gcutil list
```

List all VMs in a specific project:

```bash
./gcutil list your-project-id
```

Or using the project flag:

```bash
./gcutil list -p your-project-id
```

### SSH to a VM

```bash
./gcutil ssh INSTANCE_NAME
./gcutil ssh PROJECT.INSTANCE_NAME
./gcutil ssh INSTANCE_NAME -- -L 8080:localhost:8080  # Pass additional SSH args
```

### SCP to/from a VM

```bash
./gcutil scp LOCAL_FILE INSTANCE_NAME:REMOTE_PATH
./gcutil scp INSTANCE_NAME:REMOTE_PATH LOCAL_FILE
./gcutil scp PROJECT.INSTANCE_NAME:REMOTE_PATH LOCAL_FILE
```

### Add SSH Key to a VM

```bash
./gcutil addkey INSTANCE_NAME USERNAME KEY
./gcutil addkey INSTANCE_NAME USERNAME -f ~/.ssh/id_rsa.pub
./gcutil addkey -i INSTANCE_NAME -u USERNAME -k "ssh-rsa AAAA..."
./gcutil addkey -i INSTANCE_NAME -u USERNAME -f ~/.ssh/id_rsa.pub -p PROJECT_ID -z ZONE
```

## Example Output

```
NAME       ZONE           MACHINE TYPE   STATUS   INTERNAL IP  EXTERNAL IP
web-1      us-central1-a  n1-standard-1  RUNNING  10.0.0.1     35.1.2.3
db-prod    us-east1-b     n2-standard-4  RUNNING  10.0.0.2     35.4.5.6
test-vm    europe-west1-c e2-medium      STOPPED  10.0.0.3

Total instances: 3
```

## Testing

Run the test suite:

```bash
go test ./... -v
```

## Project Structure

```
gcutil/
├── main.go              # Entry point
├── cmd/
│   ├── root.go          # Root command and CLI setup
│   ├── auth.go          # Authentication command
│   ├── auth_test.go     # Authentication tests
│   ├── list_vms.go      # VM listing command
│   └── list_vms_test.go # VM listing tests
├── go.mod               # Go module definition
└── README.md            # This file
```

## License

MIT
