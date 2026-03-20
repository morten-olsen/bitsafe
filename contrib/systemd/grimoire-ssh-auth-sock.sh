#!/bin/sh
# Source this from ~/.bashrc or ~/.zshrc to set SSH_AUTH_SOCK
# when the grimoire service is running.
#
#   echo 'source ~/.config/grimoire/ssh-auth-sock.sh' >> ~/.bashrc
#
export SSH_AUTH_SOCK="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/grimoire/ssh-agent.sock"
