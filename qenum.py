#! /usr/bin/python

#Need pretty colours
try:
	from termcolor import colored 
except ImportError:
	print ('Termcolor appears to be missing - try: pip install termcolor')
	exit(1)

import argparse
import subprocess
import os
import sys

p = argparse.ArgumentParser("./qenum.py -H ip=10.0.0.10 -u administrator -p Password01", version="Quick Enum - Version 1.1", formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=20,width=150))

p.add_argument("-H", "--host", dest="host", help="IP Address of Target")
p.add_argument("-u", "--username", dest="username", default="",help="Enter a username")
p.add_argument("-p", "--password", dest="password", default="", help="Enter a password")
p.add_argument("-s", "--ridstart", dest="ridstart", default="500", help="RID Cycle Start - default 500")
p.add_argument("-t", "--ridstop", dest="ridstop", default="550", help="RIDCycle Stop - default 550")
p.add_argument("-f", "--func", dest="func", default="n", help="Functions - All Functions -a, Enumerate shares -s, Enumerate Domain Admins -da, Enumerate Descriptions -d")
p.add_argument("-m", "--cmethod", dest="cmethod", default="n", help="Cycle Method r for rid, e for enumdomusers")

args = p.parse_args()

def banner():
	print """
     .-')      ('-.       .-') _             _   .-')    
   .(  OO)   _(  OO)     ( OO ) )           ( '.( OO )_  
  (_)---\_) (,------.,--./ ,--,' ,--. ,--.   ,--.   ,--.)
  '  .-.  '  |  .---'|   \ |  |\ |  | |  |   |   `.'   | 
 ,|  | |  |  |  |    |    \|  | )|  | | .-') |         | 
(_|  | |  | (|  '--. |  .     |/ |  |_|( OO )|  |'.'|  | 
  |  | |  |  |  .--' |  |\    |  |  | | `-' /|  |   |  | 
  '  '-'  '-.|  `---.|  | \   | ('  '-'(_.-' |  |   |  | 
   `-----'--'`------'`--'  `--'   `-----'    `--'   `--' 
"""
	print colored("Quick Enum v1.1",'blue',attrs=['bold'])
	print colored("R Davy - NCCGroup\n",'red',attrs=['bold'])

def get_domain_sid(ip,username,password):
	#Get the domain SID	
	if username=="":
		proc = subprocess.Popen('rpcclient '+ip+' -U \"\" -N '+' -c \"lsaquery\"', stdout=subprocess.PIPE,shell=True)
	else:
		proc = subprocess.Popen('rpcclient '+ip+' -U '+username+'%'+password +' -c \"lsaquery\"', stdout=subprocess.PIPE,shell=True)
	
	stdout_value = proc.communicate()[0]

	if not "Domain Sid" in stdout_value:
		return False
	else:
		return stdout_value

def enumdomusers(ip,username,password):
	#Enumerate users using enumdomusers
	dom_accounts = []

	if username=="":
		proc = subprocess.Popen('rpcclient '+ip+' -U \"\" -N '+' -c \"enumdomusers\"', stdout=subprocess.PIPE,shell=True)
	else:
		proc = subprocess.Popen('rpcclient '+ip+' -U '+username+'%'+password +' -c \"enumdomusers\"', stdout=subprocess.PIPE,shell=True)
	
	stdout_value = proc.communicate()[0]
	
	if not "user:[" in stdout_value:
		return False
	else:
		for line in stdout_value.split('\n'):
			tmpline=line.lstrip()
			tmpline=tmpline.split(' ')
			dom_accounts.append(tmpline[0].replace("user:[", "").replace("]", ""))

	if len(dom_accounts)>0:
		
		if dom_accounts[len(dom_accounts)-1]=='':
			del dom_accounts[len(dom_accounts)-1]

		print colored('[*]Successfully extracted '+str(len(dom_accounts))+' user name(s)','green')
					
		if os.path.isfile(str(args.host)+"_users.txt"):
			os.remove(str(args.host)+"_users.txt")

		fout=open(str(args.host)+"_users.txt",'w')
		for u in dom_accounts:
			fout.write(u+"\n")
		fout.close()

		print colored('[*]User accounts written to file '+str(args.host)+"_users.txt",'green')

	else:
		print colored('[-]Looks like we were unsuccessfull extracting user names with this method','red')


def get_domain_admins(ip,username,password):
	
	da_accounts = []
	parsed_da_accounts = []
	print colored('[*]Attempting to get Domain Admins...','yellow')
		
	if username=="":
		proc = subprocess.Popen('rpcclient '+ip+' -U \"\" -N '+' -c \"querygroupmem 512\"', stdout=subprocess.PIPE,shell=True)
	else:
		proc = subprocess.Popen('rpcclient '+ip+' -U '+username+'%'+password +' -c \"querygroupmem 512\"', stdout=subprocess.PIPE,shell=True)
	
	stdout_value = proc.communicate()[0]

	for line in stdout_value.split('\n'):
		tmpline=line.lstrip()
		tmpline=tmpline.split(' ')
		da_accounts.append(tmpline[0].replace("rid:[", "").replace("]", ""))

	if len(da_accounts)>0:
		for sid in da_accounts:
			
			if username=="":
				proc = subprocess.Popen('rpcclient '+ip+' -U \"\" -N '+'  -c \"queryuser '+sid+'\"', stdout=subprocess.PIPE,shell=True)
			else:
				proc = subprocess.Popen('rpcclient '+args.host+' -U '+args.username+'%'+args.password +' -c \"queryuser '+sid+'\"', stdout=subprocess.PIPE,shell=True)
			
			stdout_value = proc.communicate()[0]
			for line in stdout_value.split('\n'):
				tmpline=line.lstrip()
				if "User Name   :	" in tmpline:
					parsed_da_accounts.append(tmpline.replace("User Name   :	", "").rstrip())
	
	if len(parsed_da_accounts)>0:
		print colored('[*]Successfully extracted '+str(len(parsed_da_accounts))+' Domain Admins','green')
		
		if os.path.isfile(str(args.host)+"_da_users.txt"):
				os.remove(str(args.host)+"_da_users.txt")

		fout=open(str(args.host)+"_da_users.txt",'w')
		for u in parsed_da_accounts:
			fout.write(u+"\n")
		fout.close()

		print colored('[*]Domain Admins written to file '+str(args.host)+"_da_users.txt",'green')
	else:
		print colored('[-]Something went wrong getting Domain Admins, Check Creds...','red')

	return parsed_da_accounts

def sid_to_name(ip,sid,username,password,start,stop):
	
	rid_accounts = []
	print colored('[*]RID Cycling in process, gathering names...','yellow')
		
	for i in range(start,stop):
		
		if username=="":
			proc = subprocess.Popen('rpcclient '+ip+' -U \"\" -N '+' -c \"lookupsids '+sid+'-'+str(i)+'\"', stdout=subprocess.PIPE,shell=True)
		else:
			proc = subprocess.Popen('rpcclient '+ip+' -U '+username+'%'+password +' -c \"lookupsids '+sid+'-'+str(i)+'\"', stdout=subprocess.PIPE,shell=True)
		
		stdout_value = proc.communicate()[0]
		
		for line in stdout_value.rstrip().split('\n'):
			rid_account = line.split(" ", 1)[1]
			if rid_account != "request" and '(1)' in rid_account and '$' not in rid_account:
				rid_account = rid_account.replace("(1)", "")
				rid_account = rid_account.rstrip()
				
				#If the account name includes domain strip it off.
				if "\\" in rid_account:
					rid_accounts.append(rid_account.split("\\", 1)[1])
				else:
					rid_accounts.append(rid_account)

	return rid_accounts

def getdescfield(ip,username,password):

	usernames = []
	descfield = []
	filename=(str(ip)+"_users.txt")

	#Start by seeing if out userfile exists, if it does read in contents
	if os.path.isfile(filename):
		print colored('[*]Enumerating usernames to get description information...','yellow')
		with open(filename,'r') as inifile:
			data=inifile.read()
			user_list=data.splitlines()
		
		#Make sure that the list of users is greater than 0
		if len(user_list)>0:
			#Confirm userfile found and its not empty
			print colored('[*]Username file found...','yellow')
			for x in xrange(0,len(user_list)):
				if '\\' in user_list[x]:
					paccount=user_list[x].split("\\", 1)[1]
				else:
					paccount=user_list[x]

				if username=="":
					proc = subprocess.Popen('rpcclient '+ip+' -U \"\" -N '+'  -c \"queryuser '+paccount+'\"', stdout=subprocess.PIPE,shell=True)
				else:
					proc = subprocess.Popen('rpcclient '+args.host+' -U '+args.username+'%'+args.password +' -c \"queryuser '+paccount+'\"', stdout=subprocess.PIPE,shell=True)
			
				stdout_value = proc.communicate()[0]
				
				if 'result was NT_STATUS_ACCESS_DENIED' in stdout_value:
					print colored('[-]Access Denied, Check Creds...','red')
					break
				else:
					for line in stdout_value.split('\n'):
						tmpline=line.lstrip()
						if "Description :	" in tmpline:
							desclen=(tmpline.replace("Description :	", "").rstrip())
							if len(desclen)>0:
								usernames.append(paccount)
								descfield.append(tmpline.replace("Description :	", "").rstrip())

		if len(descfield)>0:
			print colored('[*]Successfully extracted '+str(len(descfield))+' accounts with descriptions','green')
		
			if os.path.isfile(str(args.host)+"_desc_users.txt"):
				os.remove(str(args.host)+"_desc_users.txt")

			fout=open(str(args.host)+"_desc_users.txt",'w')
			for u in xrange(0,len(descfield)):
				fout.write(usernames[u]+","+descfield[u]+"\n")
			fout.close()

			print colored('[*]Accounts with descriptions written to file '+str(args.host)+"_desc_users.txt",'green')
			
			if os.path.isfile(str(args.host)+"_desc_users.txt"):
				proc = subprocess.Popen('grep -i pass '+str(args.host)+"_desc_users.txt", stdout=subprocess.PIPE,shell=True)
				stdout_value = proc.communicate()[0]

				if len(stdout_value)>0:
					print colored('[*]A quick check for pass reveals... '+'\n','yellow')
					print stdout_value
		
	else:
		print colored('[-]Unable to find username file...','red')

def get_shares(ip,username,password):
	parsed_shares = []

	#This will enum available shares then connect to each one using smbclient and list their contents.
	if username=="":
		proc = subprocess.Popen('rpcclient '+ip+' -U \"\" -N '+'  -c \"netshareenumall\"', stdout=subprocess.PIPE,shell=True)
	else:
		proc = subprocess.Popen('rpcclient '+ip+' -U '+username+'%'+password +' -c \"netshareenumall\"', stdout=subprocess.PIPE,shell=True)
			
	stdout_value = proc.communicate()[0]
	
	if "netname:" in stdout_value:
		for line in stdout_value.split('\n'):
			tmpline=line.lstrip()
			if "netname: " in tmpline:
				parsed_shares.append(tmpline.replace("netname: ", "").rstrip())

		if len(parsed_shares)>0:
		
			for i in parsed_shares:
				if username=="":
					proc = subprocess.Popen('smbclient '+' -U \"\" -N '+'//'+ip+'/'+i+' -c \"dir\" 2>/dev/null', stdout=subprocess.PIPE,shell=True)
				else:
					proc = subprocess.Popen('smbclient '+' -U '+username+'%'+password +' //'+ip+'/'+i+' -c \"dir\" 2>/dev/null', stdout=subprocess.PIPE,shell=True)
			
					stdout_value = proc.communicate()[0]
					if "NT_STATUS_ACCESS_DENIED" in stdout_value:
						print colored("\n[-]NT_STATUS_ACCESS_DENIED for share "+i,'red')
						print colored("[*]Credentials used - "+username+","+password+'\n','yellow')
					else:
						print colored('\n[*]Contents of Share - '+i,'green')
						print colored("[*]Credentials used - "+username+","+password+'\n','yellow')
						print stdout_value


	elif "NT_STATUS_LOGON_FAILURE" in stdout_value:
		print colored(username+" "+args.password,'red') +colored(" - NT_STATUS_LOGON_FAILURE",'red')
	elif "NT_STATUS_ACCOUNT_LOCKED_OUT" in stdout_value:
		print colored('*****WARNING***** '+username+" "+args.password,'red') +colored(" - NT_STATUS_ACCOUNT_LOCKED_OUT",'red')
	elif "NT_STATUS_ACCOUNT_DISABLED" in stdout_value:
		print colored(username+" "+args.password,'blue')+colored(" - NT_STATUS_ACCOUNT_DISABLED",'blue')
	elif "NT_STATUS_PASSWORD_MUST_CHANGE" in stdout_value:
		print colored(username+" "+args.password,'blue') +colored(" - NT_STATUS_PASSWORD_MUST_CHANGE",'blue')
	else:
		print stdout_value


def main():
	
	banner()	

	#Feature is not in menu, however if we put file= in username - will try and brute force using usernames supplied in file with password.
	if args.username[0:5]=='file=':
		targets=[]

		print colored('[*]Time to do some Cracking....','yellow')
		
		if not os.path.isfile(args.username[5:len(args.username)]):
			print colored("[-]Could not find file "+args.username[5:len(args.username)],'red')
			exit(1)	
		else:
			print colored('[*]Found username file - ','green')+colored(args.username[5:len(args.username)],'yellow')
			print colored('[*]Password to use for Cracking - ','green')+colored(args.password +'\n','yellow')

			fo=open(args.username[5:len(args.username)],"rw+")
			line = fo.readlines()
			fo.close()
	
			for newline in line:
				newline=newline.strip('\n')
				targets.append (newline);

			if len(targets)>0:
				for username in targets:
					proc = subprocess.Popen('rpcclient '+args.host+' -U '+username+'%'+args.password +' -c \"getusername;quit\"', stdout=subprocess.PIPE,shell=True)
					stdout_value = proc.communicate()[0]
										
					if "Account Name:" in stdout_value:
						print colored(username+" "+args.password ,'green')+colored(" - SUCCESSFUL LOGON",'green')
					elif "NT_STATUS_LOGON_FAILURE" in stdout_value:
						print colored(username+" "+args.password,'red') +colored(" - NT_STATUS_LOGON_FAILURE",'red')
					elif "NT_STATUS_ACCOUNT_LOCKED_OUT" in stdout_value:
						print colored('*****WARNING***** '+username+" "+args.password,'red') +colored(" - NT_STATUS_ACCOUNT_LOCKED_OUT",'red')
					elif "NT_STATUS_ACCOUNT_DISABLED" in stdout_value:
						print colored(username+" "+args.password,'blue')+colored(" - NT_STATUS_ACCOUNT_DISABLED",'blue')
					elif "NT_STATUS_PASSWORD_MUST_CHANGE" in stdout_value:
						print colored(username+" "+args.password,'blue') +colored(" - NT_STATUS_PASSWORD_MUST_CHANGE",'blue')
					else:
						print stdout_value


		sys.exit()

	if args.cmethod=='r':
	
		#Get the Domain SID
		print colored('[*]Retrieving Domain SID','yellow')
		domain_sid=get_domain_sid(args.host,args.username,args.password)
		if domain_sid!=False:
			print colored(domain_sid,'green')
		else:
			print colored('[-]Unable to obtain domain SID with lsaquery, Check Creds','red')
			sys.exit()

		tmpsid=domain_sid.split(" ")
		tmpsid=tmpsid[4].rstrip()
		parsed_dom_sid=tmpsid

		#Try rid cycling
		if domain_sid!=False:
			ret_rid_accounts=sid_to_name(args.host,parsed_dom_sid,args.username,args.password,int(args.ridstart),int(args.ridstop))
			if len(ret_rid_accounts)>0:
				print colored('[*]Successfully extracted '+str(len(ret_rid_accounts))+' user name(s)','green')
					
				if os.path.isfile(str(args.host)+"_users.txt"):
					os.remove(str(args.host)+"_users.txt")

				fout=open(str(args.host)+"_users.txt",'w')
				for u in ret_rid_accounts:
					fout.write(u+"\n")
				fout.close()

				print colored('[*]User accounts written to file '+str(args.host)+"_users.txt",'green')

			else:
				print colored('[-]Looks like we were unsuccessfull extracting user names with this method','red')
	
	if args.cmethod=='e':
		#enumdomusers
		print colored('[*]Attempting to extract users with enumdomusers','yellow')
		enumdom_users=enumdomusers(args.host,args.username,args.password)
	
	if args.func=='a':
		#Call All Routines
		#Go get description fields for accounts where description is not empty.
		getdescfield(args.host,args.username,args.password)
		#Go Find our Domain Admins.
		get_domain_admins(args.host,args.username,args.password)
		#Go Find which shares we can access.
		get_shares(args.host,args.username,args.password)
	elif args.func=='d':
		#Just get descriptions
		#Go get description fields for accounts where description is not empty.
		getdescfield(args.host,args.username,args.password)
	elif args.func=='da':
		#Just get domain admins
		#Go Find our Domain Admins.
		get_domain_admins(args.host,args.username,args.password)
	elif args.func=='s':
		#Just get shares
		#Go Find which shares we can access.
		get_shares(args.host,args.username,args.password)

if __name__ == '__main__':

	main()