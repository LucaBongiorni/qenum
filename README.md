QENUM - Quick Enum
------------------

    .-')      ('-.       .-') _             _   .-')    
   .(  OO)   _(  OO)     ( OO ) )           ( '.( OO )_  
  (_)---\_) (,------.,--./ ,--,' ,--. ,--.   ,--.   ,--.)
  '  .-.  '  |  .---'|   \ |  |\ |  | |  |   |   `.'   | 
 ,|  | |  |  |  |    |    \|  | )|  | | .-') |         | 
(_|  | |  | (|  '--. |  .     |/ |  |_|( OO )|  |'.'|  | 
  |  | |  |  |  .--' |  |\    |  |  | | `-' /|  |   |  | 
  '  '-'  '-.|  `---.|  | \   | ('  '-'(_.-' |  |   |  | 
   `-----'--'`------'`--'  `--'   `-----'    `--'   `--' 

QENUM is an attack tool which carries out commonly needed basic enumeration
tasks when probing a Domain Controller.

•	Written by Richard Davy

QENUM functionality includes:

•	User enumeration using RID cycling or Enumdomusers - user names saved to file
•	Basic password brute-forcing
•	Enumerates Domain Admins - usernames saved to file 
•	Enumerates shares, attemps to mount shares and dir
•	Enumerates user accounts which have a description field which is not empty
	usernames and descriptions saved to file for analysis

Username Gathering
------------------

[*]RID Cycle

To RID Cycle with qenum

-H target ip
-u username 
-p password
-s start RID (default 500)
-t to RID (default 550)
-m cycle method r

qenum.py -H 10.0.0.1 -u rich -p mypassword -s 500 -t 1500 -m r

For NULL Sessions
qenum.py -H 10.0.0.1 -u "" -s 500 -t 1500 -m r

Any enumerated usernames will be output to a file on the local machine

[*]Enumdomusers

To gather users with Enumdomusers

-H target ip
-u username 
-p password
-m cycle method e

qenum.py -H 10.0.0.1 -u rich -p mypassword -m e

For NULL Sessions
qenum.py -H 10.0.0.1 -u "" -m e

Any enumerated usernames will be output to a file on the local machine


Password Cracking
-----------------

To crack the password for found usernames

-H target ip
-u filename containing username list
-p password to try against each username

qenum.py -H 10.0.0.1 -u file=10.0.0.12_users.txt -p PasswordToTry


Useful Enumeration Functions
----------------------------

Functions - All Functions -a, 
			Enumerate Shares -s, 
			Enumerate Domain Admins -da, 
			Enumerate Descriptions -d

[*]All Functions

To run all enumeration functions

-H target ip
-u username 
-p password
-f a

qenum.py -H 10.0.0.1 -u rich -p mypassword -f a

[*]Enumerate Shares

This function retrieves share names and then tries to mount each one.
If successful it then does a directory listing

-H target ip
-u username 
-p password
-f s

qenum.py -H 10.0.0.1 -u rich -p mypassword -f s

[*]Domain Admins

This function retrieves a list of Domain Admins
and then saves to file ready for password attacks

-H target ip
-u username 
-p password
-f da

qenum.py -H 10.0.0.1 -u rich -p mypassword -f da

[*]Enumerate Descriptions

This function enumerates all users and looks for accounts where the description
is not empty. Accounts which meet this criteria will be saved to file.

-H target ip
-u username 
-p password
-f d

qenum.py -H 10.0.0.1 -u rich -p mypassword -f d
