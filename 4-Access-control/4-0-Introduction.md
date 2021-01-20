## Introduction

When approaching a target, it's preferable to test all controls in one section at once - often output from one control will be helpful in determining whether other controls were successful. 

All controls from Access Control section could be tested with a new feature in ZAP for testing access control and by looking into the wayback machine. To make the controls clearer to read, the descriptions is provided below.

## ZAP - access control testing

ZAP has recently added a new feature - access control testing, which is right now in Alpha. It allows for testing what a defined user can access and is an excellent way to determine if specific users have access to more than needed. It requires however, that the tester configures authentication, session management and access control need to be configured. The process may be easy or very challenging - it depends solely on how the application handles authentication. In case of security regression testing or for periodic controls of access control, configuring it may be very useful. More details can be found at: [https://www.zaproxy.org/docs/desktop/addons/access-control-testing/](https://www.zaproxy.org/docs/desktop/addons/access-control-testing/)

## The wayback machine

Oftentimes a lot of information about an application can be found via the wayback machine, which saves snapshots of applications over time. The archived version of the application may give access to resources that can help with later testing. Consider looking for robots.txt files - the file may have changed over the years, but the endpoint that are defined in it might still be accessible on the internet. Check more ideas under [https://www.bugbountyhunter.com/guides/?type=waybackmachine](https://www.bugbountyhunter.com/guides/?type=waybackmachine) and [https://medium.com/@ghostlulzhacks/wayback-machine-e678a3567ec](https://medium.com/@ghostlulzhacks/wayback-machine-e678a3567ec)
