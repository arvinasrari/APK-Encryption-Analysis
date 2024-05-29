#!/bin/bash


# APK Encryption Analysis Script
# 
# Copyright (C) 2024 Arvin Asrari Ershad
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.



# the steps that im following here are
#1. Download the apk or clone the git repository
#2. decompile the apk    
#3. search for encryption keywords in decompiled JAVA files     
#4. search for encryption terms in the decompiled native libraries files (lib/.so)
#5. push install the apk in mobile
#6. analysing functions based on search keys (radar2)
#7. finding NDK functions (readelf)
#8. uninstall apk






#usage() {                              # function to print usage  
#    echo "Usage: $0 <apk_file>"
#    exit 1
#}



#if [ $# -ne 1 ]; then                 ## Check if the correct number of arguments is provided  analyze.sh arg1 arg2   $#=2     not equal = 1
#    usage
#fi


# Set variables


#APK_FILE=$1
#DECOMPILE_DIR="decompiled_apk"
#JAVA_SEARCH_RESULTS="java_encryption_search_results.txt"
#NATIVE_SEARCH_RESULTS="native_encryption_search_results.txt"
APK_FILE=$1 
APK_BASENAME=$(basename "$APK_FILE") #base name of apk
APK_NAME="${APK_BASENAME%.*}" #remove extension
WORK_DIR="${APK_NAME}_work" 
DECOMPILE_DIR="$WORK_DIR/decompiled_apk"
JAVA_SEARCH_RESULTS="$WORK_DIR/java_encryption_search.txt"
NATIVE_SEARCH_RESULTS="$WORK_DIR/native_encryption_search.txt" 
ENCRYPTION_LIBRARY_SEARCH_RESULTS="$WORK_DIR/encryption_library_search.txt"
#LIBRARY_FILE="$DECOMPILE_DIR/lib/armeabi-v7a/libexample.so" 
OUTPUT_DIR="$WORK_DIR/output"
SEARCH_KEYS="encrypt,decrypt,AES,RSA"
#SEARCH_KEYS=$(cat searchkeys.txt)



#1
#check if the adb is available
if !command -v adb &> /dev/null; then
        echo "adb could not be found. please install the adb: apt install adb"
        exit 1 
fi

#check if the apktool is available to decompil apk
if !command -v apktool &> /dev/null; then
	echo "apktool could not be found. please install the apktool: apt install apktool"
	exit 1
fi




#cp ~/Download/"$APK_FILE" ../final-scripts

#mkdir "$APK_FILE"_TEST

#2
#decompiling the apk or xapk
echo "decompiling APK"
if [[ "$APK_FILE" == *.xapk ]]; then
	mkdir -p temp_xapk
	unzip "$APK_FILE" -d temp_xapk
	APK_FILE=$(find temp_xapk -name "*.apk" | head -n 1)
    if [ -z "$APK_FILE" ]; then
        echo "No APK found inside the XAPK"
        exit 1
    fi
fi
	
apktool d -f $APK_FILE -o $DECOMPILE_DIR #need -f for force decompile




#3 
echo "searching for encryption terms in java files"
grep -riE "encrypt|decrypt|crypto|Cipher|Key|IvParameterSpec" $DECOMPILE_DIR > $JAVA_SEARCH_RESULTS
#grep -riE $SEARCH_KEYS $DECOMPILE_DIR > $JAVA_SEARCH_RESULTS
#grep -riE "$(echo $SEARCH_KEYS | tr ',' '|')" "$DECOMPILE_DIR" > "$JAVA_SEARCH_RESULTS"
echo "Search results saved to $JAVA_SEARCH_RESULTS" 






#4
echo "Searching for encryption terms in native libraries"
mapfile -t LIBRARIES < <(find "$DECOMPILE_DIR" -type f -name "*.so") # find and all .so files and save their path

# no library
if [ ${#LIBRARIES[@]} -eq 0 ]; then
    echo "No native libraries found in the APK."
    exit 0
fi


#search for encryption terms in libraries
for LIBRARY in "${LIBRARIES[@]}"; do
    strings "$LIBRARY" | grep -iE "$(echo $SEARCH_KEYS | tr ',' '|')" >> "$NATIVE_SEARCH_RESULTS"
done
echo "Search results saved to $NATIVE_SEARCH_RESULTS"




#5
echo "Installing the APK"
if adb devices | grep -q "device$"; then
    	#first uninstall the apk incase the apk already exists instead of remove it in the end (8)
	adb uninstall "$(aapt dump badging "$APK_FILE" | awk -v FS="'" '/package: name=/{print $2}')" || true


    adb install -t "$APK_FILE"
else
    echo "No devices/emulators found. Please connect a device or start an emulator."
    exit 1
fi


#6


#if [ -z "$SEARCH_KEYS" ]; then # Set default search keys if not provided
#    SEARCH_KEYS="encrypt,decrypt,AES,RSA"
#fi
IFS=',' read -r -a SEARCH_KEYS_ARRAY <<< "$SEARCH_KEYS" # Convert comma-separated search keys to array


#create output directory if it does not exist
mkdir -p "$OUTPUT_DIR"

#this function is to disassemble using radar2 and save output
disassemble_function() { 
    local function_name=$1
    local output_file="${OUTPUT_DIR}/${function_name}.txt"
    local library_file=$2
    echo "Disassembling function: ${function_name} in library: ${library_file}"
    #r2 -A -e anal.timeout=300 -b 64 -qc "pdf @ sym.${function_name}" "$library_file" > "$output_file"
    #                                          symbol to start disassembling
    r2 -Aqc "pdf @ sym.${function_name}" "$library_file" > "$output_file"
} # analyze, quiet mode, execute and quiet         

# Function to search and analyze functions based on search keys
#analyze_functions() {
 #   local key=$1
  #  local library_file=$2
   # echo "Searching for functions containing key: ${key} in library: ${library_file}"
    #FUNCTIONS=$(r2 -Aqc "afl~${key}" "$library_file" | awk '{print $3}')
    #for function in $FUNCTIONS; do
     #   disassemble_function $function "$library_file"
    #done
#}


analyze_functions() {
    for key in "${SEARCH_KEYS_ARRAY[@]}"; do #each search key   
        for library in "${LIBRARIES[@]}"; do #each library file 
            echo "Searching for functions containing key: ${key} in library: ${library}"
            FUNCTIONS=$(r2 -Aqc "afl~${key}" "$library" | awk '{print $3}') #radar2 quiet mode analyze functions list
            #                                             awk: extracts the third column of the output, which is the function name.
            for function in $FUNCTIONS; do
                disassemble_function $function "$library"
            done
        done
    done
}

analyze_functions

echo "Analysis completed. Check the ${OUTPUT_DIR} directory for results."
