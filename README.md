
# Pidgin-Mattermost plug-in by Eion Robb 

**XXXX Work in progress** 

Connects libpurple-based instant messaging clients (such as Pidgin, Finch, Adium, bitlbee) with Mattermost server. 

## Features 

Group Discussions 

- Ability to search for channels by team (beta) 
- Ability to send and received messages (beta) 
- Ability to join a public or private channels (beta) 
- Ability to add members to a public or private channel from a list of users, identifiable by First and Last Name (under development) 

1-1 Discussions

- Ability to send and receive 1-1 messages (beta) 
- Ability to begin a new 1-1 discussion by selecting from a list of users, identifiable by First and Last Name (under development) 

Sign-in 

- Ability to sign-in using username/email & password, or AD/LDAP credentials (under development) 

## Screenshots

![s](https://cloud.githubusercontent.com/assets/177788/25235037/ccc74a20-2598-11e7-8d31-349808570c8a.png)

## Requirements

- Mattermost server version 3.8 or later 
- libpurple version 2.9.0 or later
- libpurple, libjson-glib, glib, libmarkdown2 aka discount

## Install instructions 

- Install a Mattermost server ([See instructions](https://docs.mattermost.com/guides/administrator.html#installing-mattermost)) 
- Install [Pidgin](https://pidgin.im/download/)
- Install Pidgin-Mattermost plugin
-- Restart Pidgin
-- Add new Mattermost account

### Debian-based distros
Run the following commands from a terminal
```
sudo apt-get install libpurple-dev libjson-glib-dev libglib2.0-dev git make libmarkdown2-dev build-essentials;
git clone https://github.com/EionRobb/purple-mattermost.git && cd purple-mattermost;
make && sudo make install
```

### Windows users
Windows nightly builds at https://eion.robbmob.com/libmattermost.dll - copy to Program Files\Pidgin\plugins

You'll also need [libjson-glib-1.0.dll](https://eion.robbmob.com/libjson-glib-1.0.dll) in your Program Files\Pidgin directory (*not the plugins subdirectory*) if you don't already have the Skype/Facebook/Steam/other plugin installed

## Changelog 

April 18, 2017 - Project started 
