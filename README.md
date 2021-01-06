# Linux IR Collection

This ReadMe is for a Linux IR collection tool (Open sourced from https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh). The script capacity and mode of execution was  enhanced to better fit the needs of the team and the organization. The instructions for this tool will be dvided into two aspects - *simply running the tool* and *deep dives* <br/> <br/>

## Running the script
There are two scripts that perform the job - *EnumerationScript.sh* and *LinuxIRExecution.sh*, the latter calls the former and performs some pre/post processing on collected data. Run the script using the command - <br/>
> *./LinuxIRExecution.sh* (make sure you are running as root) <br/>
> Note that there is an option for thorough tests that has not been setup yet<br/> <br/>

This script will call all other needed scripts and perfrom some pre-processing and post-processing steps, the initial collection folder is the /tmp directory
  

### Output Folder Structure
The collection tool collects its output in a folder using a naming convention - *Linux-IR-Output-date-host* which contains two main folders (*'Linux-IR-date-hostname'* and *'Linux-IR-Enumeration-FileExports-hostname-date'*). All folders will be compressed at the time of collection. Navigate into the folders to attempt to find whatever artifacts you are looking for.

The output from the first collection is collected in folders that contain .txt files (preferably open them with notepad++) and a standard output dump (open this with a bash shell if the encodings look ugly to you) . This makes it easier to grep through or run other analysis tools to search for artifacts. The second collection folder actually contains important files that were collected from the host like conf-files, etc-files, files with POSIX capabilities, history files, sgid and suid files.


## Deep Dives
This section is dedicated into making deep dives into different collection artifacts and how to understand them better
 
