
# Pidgin-Mattermost plug-in by Eion Robb 

**XXXX Work in progress** 

Connects libpurple-based instant messaging clients (such as Pidgin, Finch, Adium, bitlbee) with Mattermost server. 

## Features 

**Group Discussions**

- Ability to search for channels by team (beta) 
- Ability to send and received messages (beta) 
- Ability to join a public or private channels (beta) 
- Ability to add members to a public or private channel from a list of users, identifiable by First and Last Name (under development) 

**1-1 Discussions**

- Ability to send and receive 1-1 messages (beta) 
- Ability to begin a new 1-1 discussion by selecting from a list of users, identifiable by First and Last Name (under development) 

**Sign-in**

- Ability to sign-in using username/email & password, or AD/LDAP credentials (under development) 

## Screenshots

![s](https://cloud.githubusercontent.com/assets/177788/25235037/ccc74a20-2598-11e7-8d31-349808570c8a.png)

## Changelog 

- April 18, 2017 - Project started 

## Install Guides

Please see install guides for setting up Pidgin-Mattermost 

- [Mattermost Server Install Guide](https://github.com/it33/purple-mattermost/blob/patch-3/INSTALL.md#server-install) 
- [Windows Client Install Guide](https://github.com/it33/purple-mattermost/blob/patch-3/INSTALL.md#windows-client-install) 
- [Linux Client Install Guide](https://github.com/it33/purple-mattermost/blob/patch-3/INSTALL.md#linux-client-install-guide)

### Developer Install Guide 
 
The following pre-requisites are required for developers modifying or extending this project: 

- Mattermost server version 3.8 or later ([See install instructions](https://docs.mattermost.com/guides/administrator.html#installing-mattermost))
- libpurple version 2.9.0 or later
- libpurple, libjson-glib, glib, libmarkdown2 aka discount
