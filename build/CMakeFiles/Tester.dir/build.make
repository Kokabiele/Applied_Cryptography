# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /home/user/.local/lib/python3.9/site-packages/cmake/data/bin/cmake

# The command to remove a file.
RM = /home/user/.local/lib/python3.9/site-packages/cmake/data/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/user/mio_progetto_crittogragia

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/user/mio_progetto_crittogragia/build

# Include any dependencies generated for this target.
include CMakeFiles/Tester.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/Tester.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/Tester.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/Tester.dir/flags.make

CMakeFiles/Tester.dir/tester.cpp.o: CMakeFiles/Tester.dir/flags.make
CMakeFiles/Tester.dir/tester.cpp.o: tester.cpp
CMakeFiles/Tester.dir/tester.cpp.o: CMakeFiles/Tester.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/user/mio_progetto_crittogragia/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/Tester.dir/tester.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/Tester.dir/tester.cpp.o -MF CMakeFiles/Tester.dir/tester.cpp.o.d -o CMakeFiles/Tester.dir/tester.cpp.o -c /home/user/mio_progetto_crittogragia/build/tester.cpp

CMakeFiles/Tester.dir/tester.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/Tester.dir/tester.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/user/mio_progetto_crittogragia/build/tester.cpp > CMakeFiles/Tester.dir/tester.cpp.i

CMakeFiles/Tester.dir/tester.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/Tester.dir/tester.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/user/mio_progetto_crittogragia/build/tester.cpp -o CMakeFiles/Tester.dir/tester.cpp.s

# Object files for target Tester
Tester_OBJECTS = \
"CMakeFiles/Tester.dir/tester.cpp.o"

# External object files for target Tester
Tester_EXTERNAL_OBJECTS =

Tester: CMakeFiles/Tester.dir/tester.cpp.o
Tester: CMakeFiles/Tester.dir/build.make
Tester: /usr/lib/x86_64-linux-gnu/libssl.so
Tester: /usr/lib/x86_64-linux-gnu/libcrypto.so
Tester: CMakeFiles/Tester.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/user/mio_progetto_crittogragia/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable Tester"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/Tester.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/Tester.dir/build: Tester
.PHONY : CMakeFiles/Tester.dir/build

CMakeFiles/Tester.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/Tester.dir/cmake_clean.cmake
.PHONY : CMakeFiles/Tester.dir/clean

CMakeFiles/Tester.dir/depend:
	cd /home/user/mio_progetto_crittogragia/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/user/mio_progetto_crittogragia /home/user/mio_progetto_crittogragia /home/user/mio_progetto_crittogragia/build /home/user/mio_progetto_crittogragia/build /home/user/mio_progetto_crittogragia/build/CMakeFiles/Tester.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/Tester.dir/depend

