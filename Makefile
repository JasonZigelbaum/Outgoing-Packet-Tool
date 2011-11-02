### CSE 571 Project Makefile

#		The names of the executable files
EXECUTABLE1	= packet_sniffer
EXECUTABLE2	= 

#		Source files you want to compile
#		(NOTE: Don't include header (.h) files, or source files
#		that contain function template or class template member
#		function definitions.)
CMPL_SRCS1	= engine.cpp packet-sieve.cpp
CMPL_SRCS2	= 

#               Source files containing *only* function template or class 
#		template member function definitions: note that you
#               should always provide separate source files for template 
#               and non-template definitions (and not mix both kinds in one file).
TMPL_SRCS1	= 
TMPL_SRCS2	= 

#               Header files
HEADER_FILES1    = 
HEADER_FILES2    = 

#               Other files to turn in (Makefile, readme, output files, etc.)
OTHER_FILES     = Makefile README

#               Any special flags that should be set for compilation
SPECIAL_FLAGS  =  -DTEMPLATES_MUST_INCLUDE_SOURCE  # -DDEBUG

#               Please change this if you use a different file extension
OBJS1     = $(CMPL_SRCS1:.cc=.o)
OBJS2     = $(CMPL_SRCS2:.cc=.o)
                                                                              #
#################### CHANGE ANYTHING BELOW THIS LINE AT YOUR OWN RISK ###################

#		C++ compiler
CXX		= g++

#               All your source files (needed for executable dependency)
USER_SRCS1        = $(CMPL_SRCS1) $(TMPL_SRCS1) $(HEADER_FILES1)
USER_SRCS2        = $(CMPL_SRCS2) $(TMPL_SRCS2) $(HEADER_FILES2)
USER_SRCS         = ${USER_SRCS1} ${USER_SRCS2}

#               Provided source files (i.e., History files, etc)
PROVIDED_SRCS   =

#               All your source files (needed for executable dependency)
ALL_SRCS        = $(USER_SRCS) $(PROVIDED_SRCS)

#               All files to turn in (including readme, output files, etc)
ALL_FILES       = $(USER_SRCS) $(OTHER_FILES)

# 		libraries used on Linux
LIBS    =       -ldl -lpcap

# 		libraries used on Solaris
#LIBS    =      -lnsl  -lsocket 


#               The name of the compiler
CCC      = $(CXX)

#               The name of the previewer (pageview or ghostview)
PREVIEWER = /usr/openwin/bin/pageview -right

#               Any define flags that should be set for conditional compilation
DEFFLAGS  = -DUNIX -D_REENTRANT

#               Any -I directories with .h files that should be included
INCFLAGS  =     -I/home/cec/class/cse532/ACE_wrappers

#               Flags that are specific to SUN object code
SUNFLAGS  =    #-misalign

#               Any -L directories in which there are .so files that should
#               be linked
LIBLOCFLAGS     = -L/home/cec/class/cse532/ACE_wrappers/ace -L./

#               Any general flags that should be set for the compiler
#               NOTE: to optimize fully, change -g to -O4
CXXFLAGS  =     -Wall -W -g $(SPECIAL_FLAGS) $(INCFLAGS)

#               The concatenation of all the flags that the compiler should get
CCFLAGS = $(DEFFLAGS) $(INCFLAGS) $(LIBLOCFLAGS) $(SUNFLAGS) $(CXXFLAGS)

###
# Targets
###

all: $(EXECUTABLE1) # $(EXECUTABLE2)

#               Construct the executable
$(EXECUTABLE1): Templates.DB $(OBJS1)
	$(CXX) -o $(EXECUTABLE1) $(CCFLAGS) $(OBJS1) $(LIBS)

#               Construct the executable
$(EXECUTABLE2): Templates.DB $(OBJS2)
	$(CXX) -o $(EXECUTABLE2) $(CCFLAGS) $(OBJS2) $(LIBS)

#		Remove all junk that might be lying around
clean:
	-rm -f *.o core *.bak *~ ../toturnin ./toturnin
	-rm -fr Templates.DB SunWS_cache *.rpo TEST_TURNIN

#		Also remove the previously built executables
realclean: clean
	-rm -f $(EXECUTABLE1) $(EXECUTABLE2)

#		Preview the .h and .c files
preview:
	$(ENSCRIPT) -2Gr \
        -b$(LASTNAME)", "$(FIRSTNAME)" : $(LOGNAME)@seas.wustl.edu" \
        -p - $(ALL_FILES) | $(PREVIEWER) -

#		Change the Makefile to reflect the correct dependencies.
depend:
	-rm -f ccdep
	-rm -f eddep
	$(CXX) -xM $(CCFLAGS) $(CMPL_SRCS) > ccdep
	sed -n '1,/^# DO NOT DELETE THIS LINE/p' Makefile > eddep
	echo \#\#\# >> eddep
	cat ccdep >> eddep
	cp Makefile Makefile.bak
	mv eddep Makefile
	rm ccdep

.SUFFIXES: .cpp
.cpp.o:
	$(COMPILE.cc) $(CCFLAGS) $(OUTPUT_OPTION) $<
.cpp:
	$(LINK.cc) $(LDFLAGS) -o $@ $< $(LDLIBS)

main.o: $(ALL_SRCS) Makefile

#### To avoid Sun CC warning about having to create Templates.DB.
Templates.DB:
	@test -d $@ || mkdir $@

###
# OBJECT FILE DEPENDENCIES FOLLOW.
#
# DO NOT DELETE THIS LINE -- make depend uses it
###
