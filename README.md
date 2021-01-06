# LinuxForensics

This ReadMe is for a Linux IR collection tool (Open sourced from https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh). The script capacity and mode of execution was  enhanced to better fit the needs of the team and the tool. The instructions for this tool will be dvided into two aspects - *simply running the tool* and *deep dives* <br/> <br/>

## Running the script
There are two scripos that perform the job - *EnumerationScript.sh* and *LinuxIRExecution.sh*, the latter calls the former and runs some pre/post processing on collected data. Run     the script using the command - <br/>
> ./LinuxIRExecution.sh (make sure you are running as root)<br/> <br/>

This script will call all other needed scripts and perfrom some pre-processing and post-processing steps, the initial collection folder is the /tmp directory
  
The collection tool collects its output in two folders using a naming convention - *'Linux-IR-date-hostname'* and *'Linux-IR-Enumeration-FileExports-hostname-date'*. These two      folders will be compressed at the time of collection. Navigate into the folders to attempt to fins what artifacts you are looking for
 
