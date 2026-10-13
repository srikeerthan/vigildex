# ~/.zshrc for the mockup fixture. Every value is a same-shape fake.
# Lines 1-41 are ordinary shell setup; the two exports that matter sit on
# lines 42 and 43 so the Findings inspector can say "~/.zshrc, line 42".

export ZSH="$HOME/.oh-my-zsh"
ZSH_THEME="robbyrussell"
plugins=(git macos brew)
source "$ZSH/oh-my-zsh.sh"

# Paths
export PATH="$HOME/.local/bin:$PATH"
export PATH="/opt/homebrew/bin:$PATH"
export PATH="$HOME/.cargo/bin:$PATH"
export GOPATH="$HOME/go"
export PATH="$GOPATH/bin:$PATH"

# Editors and pagers
export EDITOR=vim
export VISUAL="$EDITOR"
export PAGER=less
export LESS="-R"

# Node
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"

# Aliases
alias ll='ls -la'
alias gs='git status'
alias gd='git diff'
alias k=kubectl

# Functions
mkcd() { mkdir -p "$1" && cd "$1"; }

# History
HISTSIZE=50000
SAVEHIST=50000
setopt HIST_IGNORE_DUPS

# Set for a one-off script months ago and forgotten. Claude Code uses it in every `claude -p` run even though a Max subscription is signed in.
export ANTHROPIC_API_KEY="sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE7Qa"
export GITHUB_TOKEN=ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE3f9a

# Work tooling
export ACME_ENV=dev
