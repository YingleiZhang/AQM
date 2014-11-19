AQM algorithm ----CSC573 TCP/IP
===
The is a modification of the AQM red algorithm with DSCP bits set priority for the traffic.
There are 3 classes, and we have

Class0    DSCP = 0x32     DSCP_factor = 0.5        Best Performance.

Class1    DSCP = 0x46     DSCP_factor = 0.7        Middle in the road

Class2    DSCP = 0x00     DSCP_factor = 0.9        Best effort 

The modification on red was based on the original code. 
The blue algorithm was implemented from scrach. 

Instruction:
Download the file and put them in the same folder.
Run "make", this will generate the kernel modules.
Run "insmod  sch_red.ko" to insert the kernel mod.
Use tc command to select the kernel mod just inserted.
