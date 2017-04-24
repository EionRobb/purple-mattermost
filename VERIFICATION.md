# Verification 

As an open source project, we greatly appreciate help from the user community in finding and reporting issues so the quality of this project can continue to increase. 

This page describes how to file bugs and how to run manual verification tests. For contributors new to open source, we also describe how to note your contributions in resumes and webpages to identify your contributions. 

## Verification Contributions 

As an open source project, we highly welcome community members interested in helping test new releases before or after release to help find and report issues. Here's different ways to contribute: 

### 1. File bugs  

You can file bug reports using GitHub. When filing, we'd highly appreciate a complete bug report with steps to reproduce, and notes on your expected and observed state. 

Here is an example: https://github.com/EionRobb/purple-mattermost/issues/4

### 2. Complete a Verification Test 

If you're using an operating system different that what has been already tested, we'd highly appreciate your help completing a test plan and letting the community know if it completed successfully, or if you found issues. 

After completing a test plan, you can make a pull request to update the [Verification section in the README file](https://github.com/it33/purple-mattermost/blob/patch-3/README.md#verification
) to let everyone know your results. 

## Recognition of Verification Contributions 

If you're interested in being identified for your role in helping and influencing open source communities, you are welcome to note verification contributions in your resume or webpage as follows: 

For running individual tests: 

- **Pidgin-Mattermost open source project (purple-mattermost)**, Verification Analyst for v1.0 release on Windows 7, May 2017. Aided in discovering and resolving 2 software issues. 

For continuous testing contributions: 

- **Pidgin-Mattermost open source project (purple-mattermost)**, Verification Analyst for Windows 10, May 2017 to Present. Aided in discovering and resolving 9 software issues to date. 

## Verification Tests 

The following outlines tests to be run when verifying the functionality of new releases of this project. 

## Win10 Tests v1.0 

Using Window 10, complete the [Windows Test Plan for Supported Operating Systems](VERIFICATION.md#windows-test-plan-for-supported-operating-systems)

## Win8 Tests v1.0 

Using Window 8, complete the [Windows Test Plan for Supported Operating Systems](VERIFICATION.md#windows-test-plan-for-supported-operating-systems)

## Win7 Tests v1.0 

Using Window 7, complete the [Windows Test Plan for Supported Operating Systems](VERIFICATION.md#windows-test-plan-for-supported-operating-systems)

## Windows Test Plan for Supported Operating Systems 

1. Set up an account on the Mattermost community server at https://pre-release.mattermost.com/.
2. Complete Pidgin-Mattermost Windows Install Guide using the account above.
3. From your Pidgin client connected to the Mattermost community server join **Public Test Channel**.
4. From Pidgen, post a message, emoji and a hyperlink to the **Public Test Channel**. 
5. From Mattermost, verify the contents are received, and post back the same message from Mattermost.
6. From Pidgin, verify the message has been received. 
