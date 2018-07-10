#!/bin/sh

set -e

if [ ! -f "build/env.sh" ]; then
    echo "$0 must be run from the root of the repository."
    exit 2
fi

# Create fake Go workspace if it doesn't exist yet.
workspace="$PWD/build/_workspace"
root="$PWD"
homedir="$workspace/src/github.com/mit-dci"
if [ ! -L "$homedir/lit" ]; then
    mkdir -p "$homedir"
    cd "$homedir"
    ln -s ../../../../../. lit
    cd "$root"
fi

# Set up the environment to use the workspace.
GOPATH="$workspace"
export GOPATH

# Run the command inside the workspace.
cd "$homedir/lit"
PWD="$homedir/lit"

# Launch the arguments with the configured environment.
if [ ! -z "$1" ]; then
	exec "$@"
fi
