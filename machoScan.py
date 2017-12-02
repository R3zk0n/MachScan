from pymacho.MachO import MachO
import argparse
import macholib
from macholib.MachO import MachO as MarkO
from termcolor import colored
import sys
def main():
    parser = argparse.ArgumentParser(description="Read Mach-O file")
    parser.add_argument('filename', help='Mach-O file to parse and print')
    parser.add_argument('--headers', '-hd', help='show informations about header', action='store_true')
    parser.add_argument('--segments', '-s', help='display all segements', action='store_true')
    parser.add_argument('--dump', '-dump', help='Dumps Data on the MachO Binary', action='store_true')
    
    args = parser.parse_args()
    m = MachO(args.filename)
    machoData = MarkO(args.filename)


    if args.dump:
    	machoData = MarkO(args.filename)
    	for (load_cmd, cmd, data) in machoData.headers[0].commands:
    		if hasattr(cmd, "segname"):
    			sectionName = getattr(cmd, 'segname', '').rstrip('\0')
    			sectionOffset = cmd.fileoff
    			sectionSize = cmd.filesize
    			print "Section: %s starts at %x and has size of %x bytes." % (sectionName, sectionOffset, sectionSize)
    	Commands = machoData.headers[0].commands
    	for i in Commands:
    		Dump = "Dumping Data: {0} \t\n\t\n".format(i)
    		print Dump




  
    if args.segments:
    		for (load_cmd, cmd, data) in machoData.headers[0].commands:
    			if hasattr(cmd, "segname"):
    				sectionName = getattr(cmd, 'segname', '').rstrip('\0')
    				sectionOffset = cmd.fileoff
    				sectionSize = cmd.filesize
    				print "Section: %s starts at %x and has size of %x bytes." % (sectionName, sectionOffset, sectionSize)
		seg_data = ("[*]")+" Segments (%d) :" % len(m.segments)
		for segment in m.segments:
			segment.display(before="\t")




    if args.headers:
    	 magic =  ("\t[+]")+" magic : 0x%x %s" % (m.header.magic, "- " + m.header.display_magic())
    	 print ("\t[+]")+" cpusubtype : 0x%s" % (m.header.cpusubtype)
    	 print ("\t[+]")+" cputype : 0x%x %s" % (m.header.cputype, "- " + m.header.display_cputype())
    	 print magic
    	 print flags

    	 if "NO_HEAP_EXECUTION" in flags:
    	 	print colored("NO_HEAP_EXECUTION Complied.", 'green')
    	 else:
    	 	print colored ("Heap Execution is Allowed. This is not ok. ", 'red')

    	 if "PIE" in flags:
    	 	print colored("Compiled with PIE", 'green')
    	 else:
    	 	print colored("Does not seem to be Compiled with PIE, This is not Ok.", 'red')
    	 
    	 if "32" in magic:
    	 	print colored("32 Bit Compiled", "yellow")
    	 else:
    	 	print colored("64 Bit Compiled", "purple")

	

if __name__ == '__main__':
	main()
