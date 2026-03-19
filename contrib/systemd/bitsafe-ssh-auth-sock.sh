#!/bin/sh
# Source this from ~/.bashrc or ~/.zshrc to set SSH_AUTH_SOCK
# when the bitsafe service is running.
#
#   echo 'source ~/.config/bitsafe/ssh-auth-sock.sh' >> ~/.bashrc
#
export SSH_AUTH_SOCK="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/bitsafe/ssh-agent.sock"
