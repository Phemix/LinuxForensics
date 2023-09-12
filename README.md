# Linux IR Collection

This ReadME is for a Linux IR collection tool (Open sourced from https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh). The script capacity and mode of execution was  enhanced to better fit the needs of the team and the organization. The instructions for this tool will be dvided into two aspects - *simply running the tool* and *deep dives* <br/> <br/>

## Running the script
There are two scripts that perform the job - *EnumerationScript.sh* and *LinuxIRExecution.sh*, the latter calls the former and performs some pre/post processing on collected data. Run the script using the command - <br/>
> *./LinuxIRExecution.sh* (make sure you are running as root) <br/>
> Note that there is an option for thorough tests that has not been setup yet<br/> <br/>

This script will call all other needed scripts and perfrom some pre-processing and post-processing steps, the initial collection folder is the /tmp directory
  

### Output Folder Structure
The collection tool collects its output in a folder using a naming convention - *Linux-IR-Output-date-host* which contains two main folders (*'Linux-IR-date-hostname'* and *'Linux-IR-Enumeration-FileExports-hostname-date'*). The parent folder will be compressed at the time of collection. Navigate into the folders to attempt to find whatever artifacts you are looking for.

The output from the first collection (*'Linux-IR-date-hostname'*) is collected in folders that contain .txt files (preferably open them with notepad++ or other good text editors), and a standard output dump (open this with a bash shell or other shell compatible tool to correctly display encoding). This makes it easier to grep through or run other analysis tools to search for artifacts. 

The second collection folder (*'Linux-IR-Enumeration-FileExports-hostname-date'*) contains important files that were collected from the host like conf-files, etc-files, files with POSIX capabilities, history files, sgid and suid files.<br/> <br/>



## Deep Dives
This section is dedicated into making deep dives into different collection artifacts and how to understand them better. The linear concepts will be skipped, and only the concepts that are considered a little more technical will be addressed. Some external resources will be provided to keep this section as less crowded as possible. The documentation will try to include links that describe the concepts that are not particularly common.

-  Sudoers configuration file - https://help.ubuntu.com/community/Sudoers
-  SELinux - https://www.redhat.com/en/topics/linux/what-is-selinux
-  Umask - https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/configuring_basic_system_settings/file-permissions-rhel8_configuring-basic-system-settings
- Cron and Anacron - https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/deployment_guide/ch-automating_system_tasks#:~:text=27.1.-,Cron%20and%20Anacron,as%20often%20as%20every%20minute.&text=However%2C%20Anacron%20can%20only%20run%20a%20job%20once%20a%20day.
-  Systemd Timers - https://wiki.archlinux.org/index.php/Systemd/Timers
- Inetd - https://www.ibm.com/support/knowledgecenter/ssw_aix_72/filesreference/inetd.conf.html
- SGID and SUID - https://www.thegeekdiary.com/what-is-suid-sgid-and-sticky-bit/
- init.d - https://www.geeksforgeeks.org/what-is-init-d-in-linux-service-management/
- rc.d - https://www.thegeekdiary.com/understanding-the-rc-scripts-in-linux/
