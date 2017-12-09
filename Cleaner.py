import lief 
import argparse
from termcolor import colored
import sys
##############################
## TODO: 
##
## Implement Windows PE Switch flags 
## Implement Linux Switch Flags. ## 
##
## If you want file output. Use Pipe. -.-{}/***
##
###Id rather work non stop
###What they call incessantly
###Than work some odd job
###Just to live life pleasantly

##############################



def main():
    parser = argparse.ArgumentParser(description="Read Mach-O file")
    parser.add_argument('filename', help='Mach-O file to parse and print')
    parser.add_argument('-a', '--all',action='store_true', dest='show_all',help='Show all information')
    parser.add_argument('--info', '-i', help='show informations info', action='store_true')
    parser.add_argument('--dyld', '-d', help='show informations dyld_info informations', action='store_true')
    parser.add_argument('--comp', '-c', help='show informations regarding Compiled Protections', action='store_true')
    parser.add_argument('--head', '-head', help="Show Header Infomation", action='store_true')
    parser.add_argument('--lib', '-lib', help="Show Libraries Information", action='store_true')
    parser.add_argument('--func', '-func', help="Show Function Details", action='store_true')




    args = parser.parse_args()
    binary = lief.parse(args.filename)
    
    if args.func or args.show_all:
    	format_str = "{:<13} {:<30}"
    	format_hex = "{:<13} 0x{:<28x}"
    	format_dec = "{:<13} {:<30d}"
    	print(format_str.format("Name:", binary.name))

    	print colored("== Main Command ==", 'red')
    	cmd = binary.main_command

    	print(format_hex.format("Entry point:", cmd.entrypoint))
    	print(format_hex.format("Stack size:", cmd.stack_size))
    	
    	print colored("== Function Starts ==", 'yellow')

    	fstarts = binary.function_starts

    	print(format_hex.format("Offset:", fstarts.data_offset))
    	print(format_hex.format("Size:",   fstarts.data_size))
    	print("Functions: ({:d})".format(len(fstarts.functions)))
    	for idx, address in enumerate(fstarts.functions):
        	print("    [{:d}] __TEXT + 0x{:x}".format(idx, address))

    print("")

    if args.info or args.show_all:
    	print "Printing Binary Infomation"
    	format_str = "{:<10} {:<10}"
    	format_hex = "{:<30} 0x{:<28x}"
    	format_dec = "{:<30} {:<30d}"
    	print(format_str.format("Name:", binary.name))
    	print(format_str.format("PIE:",          str(colored(binary.is_pie, 'yellow'))))
    	print(format_str.format("NX:",           str(colored(binary.has_nx, 'yellow'))))
    	if binary.has_nx == "False":
    		print colored("Missing NX", 'red')
    	else:
    		print colored("[*] NX Compliled [*]", 'green')
    	if binary.is_pie == "False":
    		print colored("Missing PIE!", 'red')
    	else:
    		print colored("[*] PIE is Complied [*]", 'green')
    	symb = binary.exported_symbols
    	entry = binary.entrypoint
    	func = binary.exported_functions
    	lib_b = binary.libraries
    	print colored("Binary entrypoint: %s", 'red') % entry
    	for i in func:
    		print i
    	print "\nSection Headers:"
    	for i in symb:
    		print i
    	for j in lib_b:
    		print colored("\nLibraries imported: %s", 'yellow') % j

    if args.comp or args.show_all:
    	NX = binary.has_nx
    	PIE_True = binary.is_pie
    	print colored("Binary position independent: %s", 'green') % PIE_True
    	print colored("Binary NX Protection: %s", 'green') % NX

   
    if args.dyld or args.show_all:
    	data = binary.dyld_info
    	print data
    	for idx, binfo in enumerate(data.bindings):
    		print("{:10}: {:x}".format("Address", binfo.address))

    	if binfo.has_symbol:
    	   print colored("[*] Located Symbol [******]", 'red')
           print("{:10}: {}".format("Symbol", binfo.symbol.name))


    if args.lib or args.show_all:
    	f_title = "|{:<30}|{:<10}|{:<16}|{:<22}|"
    	f_value = "|{:<30}|{:<10d}|{:<16x}|{:<22x}|"
    	print colored("[**] Libraries imported [**]", 'green')
    	print(f_title.format("Name", "Timestamp", "Current Version", "Compatibility Version"))
    	for library in binary.libraries:
        	print(f_value.format(
            	library.name,
            	library.timestamp,
            	library.current_version,
            	library.compatibility_version))
    print("")

   
    if args.head or args.show_all:
    	format_str = "{:<33} {:<30}"
    	format_hex = "{:<33} 0x{:<28x}"
    	format_dec = "{:<33} {:<30d}"
    	header = binary.header
    	flag_info = binary.header.flags_list
    	print(format_str.format("Magic:",              str(header.magic).split(".")[-1]))
    	print(format_str.format("CPU Type:",           str(header.cpu_type).split(".")[-1]))
    	print(format_hex.format("CPU sub-type:",       header.cpu_subtype))
    	print(format_str.format("File Type:",          str(header.file_type).split(".")[-1]))
    	print(format_dec.format("Number of commands:", header.nb_cmds))
    	print(format_hex.format("Size of commands:",   header.sizeof_cmds))
    	print(format_hex.format("Reserved:",           header.reserved))
    	print "\nHeader Flags Set"
    	for i in flag_info:
    		print i
    	




if __name__ == '__main__':
	main()
