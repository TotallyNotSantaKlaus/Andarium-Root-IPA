# SPDX-License-Identifier: GPL-2.0-or-later
# Root shell aliases & convenience environment for Andarium Root.
# Source via: . /odm/andarium-root/scripts/andarium-shell-rc.sh

export PS1='\[\033[1;32m\]root@andarium\[\033[0m\]:\[\033[1;36m\]$PWD\[\033[0m\]# '
alias ll='ls -la'
alias ctl='andarium-ctl'
alias logs='andarium-ctl logs 80'
alias stealth-on='andarium-ctl stealth on'
alias stealth-off='andarium-ctl stealth off'
alias frida-on='andarium-ctl frida start'
alias frida-off='andarium-ctl frida stop'
alias ssh-on='andarium-ctl ssh start'
alias ssh-off='andarium-ctl ssh stop'
alias proxy-off='andarium-ctl proxy clear'
alias certs-sync='andarium-ctl certs sync'
alias webui='andarium-ctl webui open'
alias wb='andarium-workbench'
alias spoof='andarium-spoof'
alias fw='andarium-net'
alias auto='andarium-auto'
alias macro='andarium-auto macro'

proxy_on() {
    andarium-ctl proxy set "$1"
}
alias proxy-on='proxy_on'
