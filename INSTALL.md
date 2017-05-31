# Install Guides 

## Server Install

- Install Mattermost server version 3.8 or later [per the install instructions](https://docs.mattermost.com/guides/administrator.html#installing-mattermost).

## Windows Client Install
 
### 1) Install Pidgin

Download and install [Pidgin per instructions.](https://pidgin.im/download/)
 
### 2) Install Pidgin-Mattermost 

#### a) Download the plugin installer 

Download the latest release of the Pidgin-Mattermost plugin from the [releases page](https://github.com/EionRobb/purple-mattermost/releases), which should be named `Pidgin-Mattermost-v[VERSION_NUMBER].exe`.

Notes: 

- This plugin is "open source" and its [complete source code is publicly available for review and critique.](https://github.com/EionRobb/purple-mattermost). Because it is a program that runs on your computer, and because it does not bear the digital signature of a corporation, you may encounter warnings while installing to confirm you are intentionally installing the software and are aware of its origins.

- Your browser may display a warning on download to the effect of: "Pidgin-Mattermost-v[VERSION_NUMBER].exe is not commonly downloaded and may be dangerous", you can confirm you understand the warning and select **Keep** from the menu button to continue. 

#### b) Run the installer file 

Double click on the .exe file you downloaded to start the installation. 

- You may see an "unrecognized app" warning. Click "More info" and "Run anyway" to continue and enter "Yes" to confirm when asked again.

#### c) On welcome screen click "Next" to continue

![image](https://cloud.githubusercontent.com/assets/177788/25341540/fddee14a-28bd-11e7-92d6-85ed2fbb83e7.png)

On the next screen, review and accept the standard open source license agreement, "GPLv3" if you wish to proceed. [The full license file along with summary explaination is available online.](https://github.com/EionRobb/purple-mattermost/blob/master/LICENSE) 

The following screen will show progress on the installation procedure: 

![image](https://cloud.githubusercontent.com/assets/177788/25341675/709d9f64-28be-11e7-8f99-bf7a7e4f9e9f.png)

The installer will install the Pidgin-Mattermost plugin, add the Mattermost icons to your Pidgin client, and either install the Pidgin Plugin Manager ([`libjson-glib-1.0.dll`](https://eion.robbmob.com/libjson-glib-1.0.dll)) if it's not yet installed, or upgrade the Plugin Manager if it is out-of-date. 

#### d) If your plugin manager is out-dated, you may be asked to confirm you want to upgrade

Click **OK** to continue. 

![image](https://cloud.githubusercontent.com/assets/177788/25341680/77475184-28be-11e7-98ed-d4f8fd7217d2.png)

#### e) Click "Finish" after the installer is complete 

You may optionally check "Run Pidgin" to start the application after completing the plugin installation.

![image](https://cloud.githubusercontent.com/assets/177788/25341715/9d85fe54-28be-11e7-8c9c-0efb2cb8add5.png)

### 3) Restart Pidgin

When the app is restarted, you should see a welcome screen from Pidgin with help instructions on how to get started: 

<img src="https://cloud.githubusercontent.com/assets/177788/25308341/b3c5dd14-2766-11e7-980f-6919f5d61fbb.png" width="600">

### 4) Enter your Mattermost account 

#### 1) From the Pidgin Welcome Screen, click "Add..." to add an account

<img src="https://cloud.githubusercontent.com/assets/177788/25308345/beb228ea-2766-11e7-9e3c-12564807c5d4.png" width="400">


#### 2) On the "Add Account" screen, under Protocol select "Mattermost" and enter credentials 

Select Mattermost from the dropdown list under Protocol: 

<img src="https://cloud.githubusercontent.com/assets/177788/25324543/3f8cc9c4-287b-11e7-885c-3e83f9299eac.jpg" width="400">

Enter: 

- **Username:** This may be an email address, username or AD/LDAP login attribute depending on how your Mattermost server is configured. 
- **Server:** Enter the name of your server WITHOUT `https://`
- **Password:** Enter your password

Optional: Depending on your internal IT policy, optionally check "Remember password" if you'd like Pidgin to store the information. 

When complete, click **Add** to complete the creation of your new Mattermost account. This should bring you back to the **Accounts** screen. 

GitLab (MMAUTHTOKEN) authentication workaround:

- Login to your mattermost server with your browser.
- Obtain the value of MMAUTHTOKEN cookie for your mattermost server. 
  (in Firefox: Preferences -> Privacy -> Remove individual cookies -> your mattermost server -> MMAUTHTOKEN -> Content)
- Copy it to **Password:** field.
- In **Advanced** account setup tab check **Use password as MMAUTHTOKEN**.

Note: MMAUTHTOKEN expires after a server defined time: above procedure needs
      to be repeated each time it happens.

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
sudo apt-get install libpurple-dev libjson-glib-dev libglib2.0-dev git make libmarkdown2-dev build-essential;
git clone https://github.com/EionRobb/purple-mattermost.git && cd purple-mattermost;
make && sudo make install
```
