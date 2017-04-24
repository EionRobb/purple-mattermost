# Install Guides 

## Server Install

- Install Mattermost server version 3.8 or later ([See install instructions](https://docs.mattermost.com/guides/administrator.html#installing-mattermost))

## Windows Client Install
 
### 1) Install Pidgin

Download and install [Pidgin per instructions.](https://pidgin.im/download/)
 
### 2) Enable plugins

If you don't already have Pidgin plugins (such as Skype, Facebook, Steam, etc.) enabled, enable plug-ins by downloading [libjson-glib-1.0.dll](https://eion.robbmob.com/libjson-glib-1.0.dll) and adding it to your `Program Files (x86)/Pidgin` directory 

### 3) Install Pidgin-Mattermost plugin 

1. Download the latest release of the Pidgin-Mattermost plugin from the [releases page.](https://github.com/EionRobb/purple-mattermost/releases) 
2. Copy the file to `Program Files (x86)\Pidgin\plugins`.
 
Note: If you'd like to try an unreleased version of the Pidgin-Mattermost plugin, you can download and run a nightly build, available from https://eion.robbmob.com/libmattermost.dll.  

### 4) Restart Pidgin

Restart Pidgin to enable the plugin. 

You should see a welcome screen from Pidgin with help instructions on how to get started: 

<img src="https://cloud.githubusercontent.com/assets/177788/25308341/b3c5dd14-2766-11e7-980f-6919f5d61fbb.png" width="600">

### 5) Enter your Mattermost account 

#### 1) From the Pidgin Welcome Screen, click "Add..." to add an account

<img src="https://cloud.githubusercontent.com/assets/177788/25308345/beb228ea-2766-11e7-9e3c-12564807c5d4.png" width="400">


#### 2) On the "Add Account" screen, under Protocol select "Mattermost" and enter credentials 

Select Mattermost from the dropdown list under Protocol: 

<img src="https://cloud.githubusercontent.com/assets/177788/25308346/c8836974-2766-11e7-8a50-2cfc837fe0ac.png" width="400">

Enter: 

- **Username:** This may be an email address, username or AD/LDAP login attribute depending on how your Mattermost server is configured. 
- **Server:** Enter the name of your server WITHOUT `https://`
- **Password:** Enter your password

Optional: Depending on your internal IT policy, optionally check "Remember password" if you'd like Pidgin to store the information. 

When complete, click **Add** to complete the creation of your new Mattermost account. This should bring you back to the **Accounts** screen. 

#### 3) Sign-on to Mattermost 

On the **Accounts** screen double-click on your Mattermost server to join. 

<img src="https://cloud.githubusercontent.com/assets/177788/25308357/0ebd9fe0-2767-11e7-8d20-f7d5567c5faf.png" width="600">

Once you have joined, Pidgin's **Buddy List** should appear, and include a list of all public and private channels in Mattermost, including multi-person direct message channels. 

![image](https://cloud.githubusercontent.com/assets/177788/25308409/6e46cda0-2768-11e7-99ec-fcfe3d435b6b.png)

Right click and select **Join** to join the channel. 

<img src="https://cloud.githubusercontent.com/assets/177788/25313965/9a1cbe0e-27ee-11e7-9ce8-13031af4aff3.png" width="600">

The channel is linked to Mattermost and messages you post appear on the Mattermost server. 

![image](https://cloud.githubusercontent.com/assets/177788/25313970/c79288f0-27ee-11e7-9e77-13326fb9996c.png)

The members of the channel appear to the right of the conversation. Right-click and select **IM** to open a direct message channel with anyone in the room. 

## Linux Client Install Guide 
 
For people using Debian-based distributions of Linux operating systems, you can install the Pidgin-Mattermost plug using the following commands from a terminal: 

```
sudo apt-get install libpurple-dev libjson-glib-dev libglib2.0-dev git make libmarkdown2-dev build-essentials;
git clone https://github.com/EionRobb/purple-mattermost.git && cd purple-mattermost;
make && sudo make install
```
