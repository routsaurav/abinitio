export LD_LIBRARY_PATH=.:$LD_LIBRARY_PATH

logonmgr.py "$@"

---------------------------------------------------------

#!/usr/bin/env python
######################################################################################
# logonmgr - Logon Manager for ETL environment
# Maintenance Log
#
# logonmgr [-f/ile logonfilename] <command> <args>
#               [-version]
#
#       commands:
#
#       add <connection_name> <keywords>
#       create_ts <connection_name>
#       create_userid <connection_name>
#       database <connection_name>
#       dbms <connection_name>
#       dboptions <connection_name>
#       delete <connection_name>
#       export <connection_name|all>
#       help
#       help-commands
#       info
#       last_updt_ts <connection_name>
#       last_updt_userid <connection_name>
#       list
#       load_from_textfile filename
#       server <connection_name>
#       set <connection_name> <attribute> <value>
#       show <connection_name>
#       update <connection_name> <attr1=value1 [<attr2=value2> ...]
#       userid <connection_name>
#
# logonmgr commands:
#
#       dbms <connection_name>
#        Retrieves dbms attribute for connection name
#
#       set <connection_name> <attribute> <value>
#        Sets a single attribute for a logonmgr entry
#
#       last_updt_ts <connection_name>
#        Retrieves last_updt_ts audit trail attribute for connection name
#
#       create_ts <connection_name>
#        Retrieves create_ts audit trail attribute for connection name
#
#       show <connection_name>
#        Displays all attributes for a connection name. Displays the encrypted password.
#
#       userid <connection_name>
#        Retrieves userid attribute for connection name
#
#       database <connection_name>
#        Retrieves database attribute for connection name
#
#       list No arguments
#        Lists entries in logonmgr
#
#       update <connection_name> <attr1=value1 [<attr2=value2> ...]
#        Updates one or more attributes for a logonmgr entry
#
#       server <connection_name>
#        Retrieves server attribute for connection name
#
#       help-commands
#        Shows more detailed help for commands
#
#       help
#        Shows general usage
#
#       add <connection_name> <keywords>
#        Adds an entry to logonmgr
#
#       export <connection_name>
#        Exports a logonmgr entry in add format
#
#       dboptions <connection_name>
#        Retrieves dboptions attribute for connection name
#
#       info
#        Shows logonmgr version, number of entries, last date modified.
#
#       last_updt_userid <connection_name>
#        Retrieves last_updt_userid audit trail attribute for connection name
#
#       load_from_textfile filename
#        Loads logonmgr datastore with entries exported via the export command. Expects same field order as in export command
#
#       create_userid <connection_name>
#        Retrieves create_userid audit trail attribute for connection name
#
#       delete <connection_name>
#        Removes a logonmgr entry
# Third party vendor modules - rsa, xml.dom.ext (These must be installed in
# target environments)


import shelve, sys, os, rsa, types, datetime, time, commands
import exceptions
import glob, stat, pydoc
import anydbm
anydbm._defaultmod = __import__('gdbm') #       'gdbm' type for anydbm causes the db to be created in a non-proprietary format of Linux file type 'data' rather than SQLite 3.x or Berkeley DB

#Initialize global variables
dbpath = None
eiw_ctl = None
db = None
status = 0
version = "logonmgr Version 5"

cmds = {}
command_help = {}

valid_attrs =   ['name','userid','password','server','dbms','database','dboptions']

class CommandHelp(object):
        def __init__(self,cmd=None,args=None,desc=None):
                self.cmd = cmd
                self.args = args
                self.desc = desc
        def __str__(self):
                s = "\t%s %s\n\t %s" % (self.cmd, self.args, self.desc)
                return s


class ConnectionEntryError(exceptions.Exception):
        def __init__(self,args=None):
                self.args = args

class ConnectionEntry(object):
        def __init__(self,name=None,userid=None,password=None,server=None,database=None,dbms=None,dboptions=None,attr_dict=None):
                """
                        Constructor
                        constructs a ConnectionEntry object with positional or keyword arguments or even just a dictionary attr_dict
                """
                self.name = name
                self.userid = userid
                self.password = password
                self.server = server
                self.dbms = dbms
                self.database = database
                self.create_ts = str(datetime.datetime.now())
                self.last_updt_ts = str(datetime.datetime.now())
                self.create_userid = os.environ['USER']
                self.last_updt_userid = os.environ['USER']

                if dboptions == None:
                        self.dboptions = {}
                else:
                        if type(dboptions) == types.DictType:
                                self.dboptions = dboptions
                        else:
                                raise TypeError, "dboptions must be a dictionary!"

                if attr_dict == None:
                        pass
                else:
                        self.__dict__.update(attr_dict)


        def toDict(self):
                """ Converts Connection object to a dictionary object """
                d = {}
                d['name'] = self.name
                d['userid'] = self.userid
                d['password'] = self.password
                d['server'] = self.server
                d['dbms'] = self.dbms
                d['dboptions'] = self.dboptions
                d['database'] = self.database
                d['create_ts'] = self.create_ts
                d['last_updt_ts'] = self.last_updt_ts
                d['create_userid'] = self.create_userid
                d['last_updt_userid'] = self.last_updt_userid
                d['type'] = 'connection'
                return d

        def __str__(self):
                """
                 returns a string representation of this object when passed to the
                 str function with password containing [encrypted]
                """
                s = '{'
                for field in ['name','userid']:
                        s += field + ":" + str(self.__dict__.get(field,None)) + ","
                if self.password:
                        s += "password:[encrypted],"
                else:
                        s += "password:None,"
                for field in ['server','dbms','dboptions','database','create_ts','last_updt_ts','create_userid','last_updt_userid']:
                        s += field + ":" + str(self.__dict__.get(field,None)) + ","
                s += '}'
                return s

def list(args):
        """
                list keys of Connection entries
        """
        keys = sorted(db.keys())
        for key in keys:
                if key == 'eiw_ctl':
                        pass
                else:
                        print key

def query(args):
        """
                Return results matching query
        """
        #print args
        criteria = []
        params = args[1:]
        keys = db.keys()
        for arg in args:
                if '=' in arg:
                        (searchkey,v) = arg.split('=')
                        criteria.append((searchkey,v))
        s_criteria = set(criteria)
        #print "criteria is: ", s_criteria
        for key in keys:
        #       print "value of key is: ",key
                entry = db[key]
                if not type(entry) == type(()):
                        searchattrs = [ x for x in entry.__dict__.items() if x[0] != 'dboptions']
                        searchset = set(searchattrs)
                        if s_criteria.issubset(searchset):
                                print entry

def info(args):
        """
                Prints summary information about logonmgr, including version, last date updated, number of entries and path of logons file
        """
        print version
        print "logons file path: %s" % dbpath
        print "Last modification: %s" % str(time.ctime(os.path.getmtime(dbpath)))
        print "Number of entries: %d" % len(db.keys())

def export(args):
        """     Write logons file to pipe-delimited textfile """
        entry = None
        field_list = []
        fields = []
        if len(args) > 1:
                keys = [args[1]]
        else:
                keys = sorted(db.keys())

        if len(args) > 2:
                field_list = args[2:]


        for k in keys:
                try:
                        if k != 'eiw_ctl':
                                entry = db[k]
                                work_password = entry.password
                                if work_password is None:
                                        password = ''
                                else:
                                        password = rsa.decrypt(entry.password,eiw_ctl[1])

                                if len(field_list):
                                        for field in field_list:
                                                if field == 'password':
                                                        fields.append(password)
                                                else:
                                                        fields.append(entry.__dict__[field])
                                        export_rec = '|'.join(fields)
                                else:
                                        export_rec = "%s|%s|%s|%s|%s|%s" % (entry.name, entry.userid, password, entry.server, entry.dbms, entry.database)
                                print export_rec
                except KeyError,e:
                        sys.stderr.write("Invalid Key: Record=%s,key=%s\n" % (entry,e))


def gen_add_cmd(args):
        """
                export a connection name for logonmgr add format
        """

        global status
        keys = []

        if args[1].lower() == "all":
                keys = db.keys()
        else:
                keys.append(args[1].lower())

        for key in keys:
                if key == 'eiw_ctl':
                        continue

                entry = db.get(key.lower(),None)
                if entry is None:
                        sys.stderr.write('Connection Entry ' + args[1] + ' not found\n')
                        status = 1

                userid = ''
                password = ''
                server = ''
                database = ''
                dbms = ''
                dboptions = ''


                if entry.userid:
                        userid = "userid=" + entry.userid

                if entry.password:
                        password = "password=" + rsa.decrypt(entry.password,eiw_ctl[1])

                if entry.server:
                        server = "server=" + entry.server

                if entry.dbms:
                        dbms = "dbms=" + entry.dbms

                if entry.database:
                        database = "database=" + entry.database

                if entry.dboptions:
                        dboptions = "dboptions=" + '"' + str(entry.dboptions) + '"'

                if args[1].lower() == "all":
                        cmd = ''
                else:
                        cmd = 'logonmgr add '

                print "%s %s %s %s %s %s %s %s" % (cmd, entry.name, userid, password, server, database, dbms, dboptions)

def add(args):
        """
                add
                Add a new connection entry to the logons file.
                Also updates an entry if it already exists.
                Automatically encrypts a password using RSA 256.
        """

        # If connection name already exists print message and exit

        entry = db.get(args[1].lower(),None)
        if entry != None:
                sys.stderr.write('Connection Entry ' + args[1] + ' Already exists\n')
                return

        params = args[1:]


        attr_dict = {'name' : None, 'userid' : None, 'password' : None, 'server' : None, 'database' : None, 'dboptions' : None, 'dbms' : None}

        if params[0].find('=') >= 0:
                raise ValueError, "Expected connection name but found keyword"
        else:
                name = params[0].lower() # force key to be lower case
                attr_dict['name'] = name


        for param in params[1:]:
                key, value = param.split('=',1)
                if key == 'password':
                        value = rsa.encrypt(value,eiw_ctl[0])
                if key == 'dboptions':
                        d = eval(value)
                        if type(d) == types.DictType:
                                attr_dict['dboptions'] = d
                else:
                        if key in attr_dict:
                                attr_dict[key] = value
                        else:
                                raise AttributeError, "Invalid keyword:" + key

        entry = ConnectionEntry(attr_dict=attr_dict)
        db[name] = entry

def update(args):
        """
                update <conn_name> attr1=value1 [attr2=value2] ...
                update is used to set multiple attributes of a connection name
                using keyword arguments
        """
        #print "in update function"
        if len(args) < 3:
                sys.stderr.write("Usage: update <connection_name> keyword_args\n")
                return

        entry = db.get(args[1].lower(),None)
        if entry is None:
                sys.stderr.write('Connection Entry ' + args[1] + ' not found\n')
                return

        params = args[1:]


        valid_attr_names = ['userid','password','server','database','dbms','dboptions']

        attr_dict = {}

        if params[0].find('=') >= 0:
                raise ValueError, "Expected connection name but found keyword"
        else:
                name = params[0].lower() # force key to be lower case

        for param in params[1:]:
                key, value = param.split('=')
                if key == 'password':
                        value = rsa.encrypt(value,eiw_ctl[0])
                if key == 'dboptions':
                        d = eval(value)
                        if type(d) == types.DictType:
                                if not entry.dboptions:
                                        entry.dboptions = {}
                                entry.dboptions.update(d)
                else:
                        if key in valid_attr_names:
                                entry.__dict__[key] = value
                        else:
                                raise AttributeError, "Invalid keyword:" + key
        entry.last_update_userid = os.environ['USER']
        entry.last_updt_ts = str(datetime.datetime.now())
        db[name] = entry
        print "updated %s" % name

def rm_options(args):
        """
                Removes one or more option from dboptions if option name
                is found in dboptions dictionary of entry.      If all or ALL is supplied, all options
                are removed.
                rm_options <connection_name> <optionname1> <optionname2> . . . | ALL|all
        """
        there_were_updates = False

        if len(args) < 3:
                sys.stderr.write("Usage: rm-options <connection_name> optionname(s)\n")
                return

        name = args[1]
        entry = db.get(args[1].lower(),None)
        if entry is None:
                sys.stderr.write('Connection Entry ' + args[1] + ' not found\n')
                return



        if not entry.dboptions:
                print "There are no dboptions to remove."
                return

        params = args[1:]

        for param in params[1:]:
                if param.upper() == 'ALL':
                        entry.dboptions = {}
                        print "dboptions have been cleared for entry %s" % args[1]
                        there_were_updates = True
                        break
                else:
                        if param in entry.dboptions:
                                del entry.dboptions[param]
                                there_were_updates = True
                                print "option %s removed" % param
                        else:
                                print "%s is not in dboptions dictionary." % param

        if there_were_updates:
                entry.last_update_userid = os.environ['USER']
                entry.last_updt_ts = str(datetime.datetime.now())
                db[name] = entry
                print "updated dboptions for %s" % name
        else:
                print "There was nothing to update for entry %s" % args[1]


def getattr(args):
        """
                getattr
                getattr is used to dynamically get the value of an attribute by name
                uses the __dict__ dictionary of object to retrieve the attribute
        """

        global status

        if len(args) < 2:
                sys.stderr.write("Usage: logonmgr %s <connection_name>\n" % args[0])
                sys.exit(1)

        entry = db.get(args[1].lower(),None)
        if entry is None:
                sys.stderr.write('Connection Entry ' + args[1] + ' not found\n')
                status = 1
                return
        if len(args) > 2 and args[0] == 'password' and args[2] == 'decrypt' and entry.password != None:
                print rsa.decrypt(entry.__dict__[args[0]],eiw_ctl[1])
        else:
                print entry.__dict__[args[0]]

def setattr(args):
        """
                set
                set selected attribute for connection name to value
        """
        print args
        if args < 4:
                raise SystemError, "Invalid number of arguments!"

        if args[2] in valid_attrs:
                pass
        else:
                raise AttributeError, "Invalid attribute: %s" % args[2]

        entry = db.get(args[1].lower(),None)
        if entry is None:
                sys.stderr.write('Connection Entry ' + args[1] + ' not found\n')
                return

        if      args[2] == 'password':
                password = rsa.encrypt(args[3],eiw_ctl[0])
                entry.password = password
        elif args[2] == 'dboptions':
                d = eval(args[3])
                if type(d) == types.DictType:
                        entry.dboptions.update(d)
                else:
                        raise TypeError, "%s cannot be converted to a dictionary type!" % args[3]
        else:
                entry.__dict__[args[2]] = args[3]

        entry.last_updt_ts = str(datetime.datetime.now())
        entry.last_updt_userid = os.environ['USER']

        db[args[1].lower()] = entry

def show(args):
        """
                show
                display string representation of a ConnectionEntry
        """

        global status
        if len(args) < 2:
                sys.stderr.write( "usage: logonmgr show <connection_name>\n")
                sys.exit(1)

        entry = db.get(args[1].lower(),None)
        if entry is None:
                sys.stderr.write('Connection Entry ' + args[1] + ' not found\n')
                status = 1
        print str(entry)



def delete(args):
        """
                delete
                delete ConnectionEntry from logons file
        """

        entry = db.get(args[1].lower(),None)
        if entry is None:
                sys.stderr.write('Connection Entry ' + args[1] + ' not found\n')
        del db[entry.name]
        print "Entry " + entry.name + " deleted."

def load_from_textfile(args):
        if len(args) < 2:
                sys.stderr.write("Filename is required.\n")
                sys.exit(2)
        text_file = open(args[1])
        print "processing file: " + args[1]
        count = 0
        for line in text_file:
                try:
                        (name,userid,password,server,dbms,database) = line.rstrip().split('|')
                        newentry = ConnectionEntry(name.lower(),userid=userid,password=rsa.encrypt(password,eiw_ctl[0]),server=server, database=database,dbms=dbms)
                        db[name.lower()] = newentry
                        print "Imported " + name
                        count = count + 1
                except Exception, e:
                        print 'Error processing record: %s. Error=%s\n' % (line,e)
        print "Imported %s records" % count

def bulk_add(args):
        """
        bulk_add <logon_args_file>
        Adds several entries to a logonmgrdb that are in connection name and key=value format.
        """
        if len(args) < 2:
                print >> sys.stderr, "Usage: logonmgr bulk_add <args_file>"
                sys.exit(1)

        args_file_path = args[1]
        f = open(args_file_path)
        for line in f:
                add_args = ['add']
                add_args += line.strip().split()
                add(add_args)


def import_logons(args):
        """
                import dbaccess|adwlogons
                Imports logon information from either the HOME/dbaccess files or from
                the centralized adw logon file
        """

        try:
                adwlogon_dir = os.environ['ADWCMNDIR'] + '/td/env'
        except Exception, e:
                sys.stderr.write("Could not access ETLCMNDIR environment variable: %s\n" % e)
                sys.exit(2)


        if len(args) < 2:
                sys.stderr.write("dbaccess or adwlogons type required!\n")
                sys.exit(2)

        if args[1] == "dbaccess":
                print "importing dbaccess file"
                dbaccess = dbm.open(os.environ['HOME'] + '/dbaccess')
                keys = dbaccess.keys()
                for key in keys:
                        userid, password = dbaccess[key].split(',')
                        newentry = ConnectionEntry(key.lower(),userid=userid,password=rsa.encrypt(password,eiw_ctl[0]), database=key,dbms='db2')
                        db[key.lower()] = newentry
                        print "added %s" % key.lower()
        elif args[1] == "adwlogons":
                print "importing logons from ADW logon files"
                os.chdir(adwlogon_dir)
                files = glob.glob('*logon.dat')
                for f in files:
                        if os.access(f,os.R_OK):
                                logon_string = open(f,'r').read().strip()
                                print f + ":" + logon_string
                                if logon_string == '':
                                 print "logon for %s is empty. Skipped." % f
                                 continue
                                logon_pos = logon_string.find('.logon')
                                if logon_pos >= 0:
                                        connection_string = logon_string[logon_pos + 6:]
                                else:
                                        connection_string = logon_string
                                tpid,logonpwd = connection_string.split('/')
                                logon, password = logonpwd.split(',')
                                dbms = 'teradata'
                                connection_name, ext_string = os.path.splitext(f)
                                password = rsa.encrypt(password,eiw_ctl[0])
                                attrs = { 'name' : connection_name.lower(), 'server': tpid, 'dbms':dbms,
                                                'userid':logon,'password':password}
                                print attrs
                                entry = ConnectionEntry(attr_dict=attrs)
                                db[connection_name.lower()] = entry
                        else:
                                print "%s is not readable. Cannot import." % f
        else:
                sys.stderr.write(args[1] + ' is an invalid import type\n')

def usage():

        print """ logonmgr [-l] [-f/ile logonfilename] <command> <args>
                                commands:
                        """
        c_list = command_help.keys()
        c_list.sort()
        for c in c_list:
                print "\t%s %s" % (command_help[c].cmd,command_help[c].args)
        print
        print """ For more detailed help on commands.   Enter the help-commands command. """

def help_general(args):
        print """ logonmgr is a utility that lets users and programs manage database and application
                                connection parameters.  This information is stored in an object datastore utilizing
                                plain python shelve files.
                        """

        usage()
        print
        print """ OPTIONS
                                -l/ocal This option will cause logonmgr to access $HOME/logons. It is valid for
                                                Developers NOT BatchIDs
                                                The default datastore is $APP_OBJECTS_DIR/logons.gdbm

                                -f/ile  <logonfile>      This options lets you specify a datastore path other than the
                                                default or $HOME logons file.
                                                The default datastore is $APP_OBJECTS_DIR/logons.gdbm
                        """


def register_help_commands():
        getters = ['userid','server','dbms','database','dboptions']
        auditors = ['create_userid','create_ts','last_updt_userid','last_updt_ts']
        command_help['add'] = CommandHelp('add','<connection_name> <keywords>', 'Adds an entry to logonmgr')
        command_help['delete'] = CommandHelp('delete','<connection_name>','Removes a logonmgr entry')
        command_help['set'] = CommandHelp('set','<connection_name> <attribute> <value>','Sets a single attribute for a logonmgr entry')
        command_help['update'] = CommandHelp('update','<connection_name> <attr1=value1 [<attr2=value2> ...]',
                                                'Updates one or more attributes for a logonmgr entry')
        command_help['rm-options'] = CommandHelp('rm-options','<connection_name> <optionname1> <optionname2> ... |ALL|all',
                                                'removes one, more or all options from a dboptions dictionary for an entry')
        command_help['list'] = CommandHelp('list','No arguments','Lists entries in logonmgr')
        command_help['show'] = CommandHelp('show','<connection_name>', 'Displays all attributes for a connection name. Displays the encrypted password.')
        command_help['export'] = CommandHelp('export','<connection_name>|all','Exports logonmgr entry or all entries in pipe-delimited format')
        command_help['gen-add-cmd'] = CommandHelp('gen-add-cmd','<connection_name>|all','Exports logonmgr entry or all entries in logonmgr add format')
        command_help['load_from_textfile'] = CommandHelp('load_from_textfile','filename','Loads logonmgr datastore with entries exported via the export command. Expects same field order as in export command')
        for getter in getters:
                command_help[getter] = CommandHelp(getter,'<connection_name>','Retrieves %s attribute for connection name' % getter)
        for auditor in auditors:
                command_help[auditor] = CommandHelp(auditor,'<connection_name>','Retrieves %s audit trail attribute for connection name' % auditor)

        command_help['help-commands'] = CommandHelp('help-commands','','Shows more detailed help for commands')
        command_help['info'] = CommandHelp('info','','Shows logonmgr version, number of entries, last date modified, location of db')
        command_help['help'] = CommandHelp('help','','Shows general usage')

def help_commands(args):
        help_text = 'logonmgr commands:\n'
        for c in command_help:
                help_text += '\n' + str(command_help[c]) + '\n'

        pydoc.pager(help_text)

cmds = { 'list' : list, 'add' : add, 'delete' : delete, 'userid' : getattr,
                 'password' : getattr, 'server' : getattr, 'dbms' : getattr, 'database': getattr,
                 'dboptions' : getattr ,'show' : show , 'set': setattr,
                 'update': update, 'query' : query, 'create_ts' : getattr,
                 'rm-options' : rm_options,
                 'create_userid' : getattr, 'last_updt_ts' : getattr, 'last_updt_userid' : getattr,
                 'export' : export, 'load_from_textfile' : load_from_textfile, 'help-commands' : help_commands ,
                 'bulk_add' : bulk_add, 'help' : help_general, 'gen-add-cmd' : gen_add_cmd,'info' : info}

read_only_cmds = ['list','show','userid','server','password','dboptions',
                                'query','export','database','dbms','create_userid','last_updt_ts','create_ts','last_updt_userid']

def init():
        """
                Initialize logonmgr variables
        """
        global logons_dir, dbpath, db
        logons_dir = os.environ.get('APP_OBJECTS_DIR',None)
        if logons_dir:
                dbpath = logons_dir + '/logons.gdbm' #set default dbpath to APP_OBJECTS_DIR/logons.gdbm
        else:
                dbpath = "UNKNOWN"      # if APP_OBJECTS_DIR nonexistant then -f or -l must be used below

def create_logons_gdbm(old_dbpath):
        """
        this function is called when the batchID or developer has an old logons.db file but there is not a new logons.gdbm file
        this function will create a new logons.gdbm in a non-proprietary format using the export file from the old one logons.db
        """
        print "Creating a new logons.gdbm in a non- proprietary format using the export file from the old logons.db"
        exp_file = old_dbpath + ".exp"
        cmd="logonmgr.old -f %s export | sort > %s" % (old_dbpath, exp_file)
        status,output = commands.getstatusoutput(cmd)
        if status or output != "":
                print "  *** ERROR  -  logonmgr.old export FAILED ***"
                print output
                print status
                sys.exit(1)

        load_from_textfile(("dummy",exp_file))
        os.remove(exp_file)


#######   MAINLINE   ########

#validate parms
if __name__ == "__main__":

        register_help_commands()

        if len(sys.argv) < 2:
                help_general(0)
                sys.exit(1)
        args = sys.argv


        init()

        #######################
        # process options
        ########################

        # check for -version option
        if args[1] == '-version':
                print version
                sys.exit(0)

        # first check for -local option
        localOK = False
        if args[1] == '-local' or args[1] == '-l':
                hostname = os.uname()[1]
                dbpath = os.environ['HOME'] + '/logons.gdbm'
                if os.path.exists(dbpath + '.' + hostname):
                        dbpath = dbpath + '.' + hostname
                del args[1]
                cmd="grep `whoami` /etc/passwd | cut -d':' -f6 | grep ^/home"
                status,output = commands.getstatusoutput(cmd)
                if output == "" or status:
                        print "FATAL ERROR - -l option NOT available to BatchIDs"
                        sys.exit(1)
                if len(args) < 2:
                        print "FATAL ERROR - -l option requires a command"
                        sys.exit(1)
                localOK = True

        if args[1] == '-f' or args[1] == '-file':
                if len(args) < 3:
                        print "FATAL ERROR - File argument is required! for -f option"
                        sys.exit(1)
                dbpath = args[2]
                del args[1:3]

        if dbpath == "UNKNOWN":
                print "FATAL ERROR - You MUST have APP_OBJECTS_DIR set or use -f or -l option to point to logons file"
                sys.exit(2)

        cmd = args[1]

        if cmd not in cmds:
                print cmd + " is invalid."
                help_general(0)
                sys.exit(3)

        #open for read or read-write access depending on cmd
        #       unless file does not exist then create it.
        if os.path.exists(dbpath):
                open_flag = 'r' if cmd in read_only_cmds else 'c'
        else:
                print "Creating new file: " + dbpath
                open_flag = 'c'

        #Initialize encryption keys if they don't exist
        try:
                db = shelve.open(dbpath,flag=open_flag,protocol=-1)
        except Exception, e:
                print "Unable to open %s:" % dbpath , e
                sys.exit(4)

        eiw_ctl = db.get('eiw_ctl',None)

        if eiw_ctl == None:
                (pubkey, privkey) = rsa.newkeys(512)
                eiw_ctl = [(pubkey), (privkey)]
                print 'new eiw_ctl'
                db['eiw_ctl'] = eiw_ctl
#               if creating new logons.gdbm and and old logons.db exists in same path then call create_logons_gdbm to copy all entries
                old_dbpath = dbpath.replace('/logons.gdbm','/logons.db')
                if os.path.exists(old_dbpath):
                        create_logons_gdbm(old_dbpath)
                        print
                        #cmd_ls="ls -l $HOME/logons*"
                        #status,output = commands.getstatusoutput(cmd_ls)
                        #print output
                        #print status

        cmds[cmd](args[1:])
        sys.exit(status)
