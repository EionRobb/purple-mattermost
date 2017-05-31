
# Pidgin-Mattermost plugin by Eion Robb 

Connects libpurple-based instant messaging clients (such as Pidgin, Finch, Adium, bitlbee) with Mattermost server. 

## Features 

**Setup & Navigation**

- Installer for setting up Pidgin-Mattermost with Pidgin.
- Connect to Mattermost server using email/username & password. 
- Connect to Mattermost server using AD/LDAP credentials. 
- Connect to Mattermost server using GitLab authentication (MMAUTHTOKEN workaround).
- Automatically add buddies and joined channels to buddylist.
- Unjoined channels displayed in Room List picker to be joined.
- User search via **Accounts > {Mattermost Account} > Search for Users...**

**Core Communication**
 
- Send and receive messages, including weblinks and emoji.  
- Display of online/offline/away status. 
- Sending of read notifications so the server understands users is still online. 
- Display of messages sent while Pidgin was offline. 
- Mark messages edited by a Mattermost user as "Edited:"
- If Mattermost [enables public file links](https://docs.mattermost.com/administration/config-settings.html#enable-public-file-links) (off by default) file sharing links can be displayed in Pidgin. 

**Group Discussions**

- Join a public and private channels and multi-party direct message channels by right-clicking on channel in Buddy List and selecting. 


**1-1 Discussions**

- Open Direct Message discussions from a Room by right-clicking on the user name and selecting **IM**.

**Advanced Mattermost Features**

- Support for most [built-in Mattermost Slash Commands](https://docs.mattermost.com/developer/slash-commands.html).

## Screenshots

![s](https://cloud.githubusercontent.com/assets/177788/25235037/ccc74a20-2598-11e7-8d31-349808570c8a.png)

## End User Install Guides

Please see install guides for setting up Pidgin-Mattermost 

- [Mattermost Server Install Guide](INSTALL.md#server-install) 
- [Windows Client Install Guide](INSTALL.md#windows-client-install) 
- [Linux Client Install Guide](INSTALL.md#linux-client-install-guide)

This plugin includes it own installer for setting up on Windows: 

![s](https://cloud.githubusercontent.com/assets/177788/25341540/fddee14a-28bd-11e7-92d6-85ed2fbb83e7.png) 

### Developer Install Guide 
 
For modifying or extending this project please follow the [Linux Client Install Guide](INSTALL.md#linux-client-install-guide) to set up your environment. 

## Changelog 

- April 18, 2017 - Pidgin-Mattermost v0.0 - Project started 
- April 23, 2017 - Pidgin-Mattermost v1.0 - Initial Release   

## Verification 

The following table outlines the results of verification tests completed on different client platforms. 

| Version | Verification Plan | Analyst | Verification Date | Bugs Found |  
| :--- | :--- | :--- | :--- | :--- | 
| Pidgin 1.0 | [Win10 Tests v1.0](VERIFICATION.md#win10-tests-v10) | Ian Tien | April 23, 2017 | [#4](https://github.com/EionRobb/purple-mattermost/issues/4) | 

Contributions to testing and verifying this projects are highly welcome, read our [verification contributions documentation to learn how you can help.](VERIFICATION.md#verification-contributions) 
