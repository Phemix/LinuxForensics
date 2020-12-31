# LinuxForensics

This ReadMe is for a Linux IR collection tool (Open sourced from https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh). The script capacity and mode of execution was  enhanced to better fit the needs of the team and the tool. The instructions for this tool will be dvided into two aspects - simply running the tool and deep dives


i. Running the tool
  There are two scripos that perform the job - EnumerationScript.sh and LinuxIRExecution.sh, the latter calls the former and runs some pre/post processing on collected data. Run     the script using the command - 
      LinuxIRExecution.sh (make sure you are running as root)
  
  The collection tool collects its output in two folders using a naming convention following host
 
