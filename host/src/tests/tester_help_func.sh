#!/bin/sh
# Helper functions for testers scripts

# Default CC driver
if [[ -z $CC_DRIVER_NAME ]]; then
	if [ `uname -m` == x86_64 ]; then # ! native platform
		echo "*** Assuming x86_64 platform ***"
	elif [ `uname -m` == armv7l ] || [ `uname -m` == aarch64 ]; then # ! ARM/Zynq/Juno platform
		drivername=arm_ccree
		dx_device=$(find /sys/devices -name "*$drivername")
		if [ "$dx_device" == "" ]; then
			echo "******!!!  Unknown CC device type! Assumed Softcrys platform ! ******"
			echo "****** If your project is not Softcrys, then check *.dtb file ! *****"
		else
			dx_device=$(find /sys/devices/ -name *$drivername | awk -F"." '{print $2}')  # Remove /sys directory path prefix

			if [ "$dx_device" == "$drivername" ]; then
				export CC_DRIVER_NAME=ccree
				export CC_DEV=cc7xree
			else
				echo "****** Unknown CC device name (dx_device=$dx_device) ******"
			fi
		fi
	else
		echo "***** Unsupported platform ****"
		exit 1
	fi
fi


echo CC_DEV=$CC_DEV  CC_DRIVER_NAME=$CC_DRIVER_NAME  CC_DEV_NAME=$CC_DEV_NAME

is_sos=`uname -r | grep -- -sos-`
if [[ "$is_sos" != "" ]]; then
	# Identified Linux kernel for SierraOS (Assumes kernel version include "-sos-")
	echo "Assuming Linux kernel is non-secure (`uname -r`)"
	LINUX_NS=1
else
	LINUX_NS=0
fi

#default log file name
if [[ -z $LOG_FNAME ]]; then LOG_FNAME=logs/`basename $0 .sh`.log; fi

TEST_SUCCESS_CNT=0
TEST_WARN_CNT=0
TEST_FAIL_CNT=0
TEST_DISABLED_CNT=0

# Escape sequences for console output
STAT_COL=80
TAB="\011"
ESC="\033"
CSI="${ESC}["
CSR_SAVE="${CSI}s"
CSR_RESTORE="${CSI}u"
CSR_STAT_COLUMN="${CSI}${STAT_COL}G"
ERASE_TO_EOL="${CSI}K"
MODE_NORMAL="${CSI}0m"
MODE_BRIGHT="${CSI}1m"
MODE_FAINT="${CSI}2m"
COLOR_DEFAULT="${CSI}39m"
COLOR_RED="${CSI}31m"
COLOR_GREEN="${CSI}32m"
COLOR_YELLOW="${CSI}33m"

# Reset CryptoCell
# PoR - reset towards CryptoCell, the AO module and the ENV REGs (without the ROSC)
reset_cc() {
	# get CC_ENV base address
	FIND_LINE=`find /sys/ -name *arm_cc* | grep arm_cc_env@`
	CC_ENV_BASE="${FIND_LINE#*arm_cc_env@}"

	# calculate register address
	CC_ENV_FPGA_CC_POR_N_ADDR_REG_OFFSET=0x00E0
	CC_POR_N_ADDR=$((CC_ENV_BASE + CC_ENV_FPGA_CC_POR_N_ADDR_REG_OFFSET))

	# reset CryptoCell
	devmem $CC_POR_N_ADDR 32 0x1
	if [[ $? -ne 0 ]]; then
		exit 1
	fi
}

# Pad given string to given length
# \param $1 String to pad
# \param $2 Result string length
# \param $3 Padding character (default is " ")
pad_string() {
	local pad_char
	local pad_len
	if [[ "$3" == "" ]]; then
		pad_char=' '
	else
		pad_char=`expr substr "$3" 1 1`
	fi

	pad_len=$(( $2 - ${#1} ))
	echo -n $1
	for i in `seq 1 $pad_len`; do
		echo -n "$pad_char"
	done
}

# Start logging mechanism
# \param $1 log filename (optional)
start_log() {
	if [[ "$1" != "" ]]; then
		LOG_FNAME=$1
	fi
	# Create parent directory if available
	LOG_PATH=`dirname $LOG_FNAME`
	if [[ "$LOG_PATH" != "." ]]; then mkdir -p $LOG_PATH ; if [[ $? -ne 0 ]]; then echo "Failed creating directory $LOG_PATH"; exit 1; fi ; fi
	echo `date`: Logging tests output to $LOG_FNAME
	echo "`date`: Test started" > $LOG_FNAME
	TEST_START_TIME=`date +%s`
}

# echo and log message
# \param $1 message
echo_log() {
	echo -e "$1"
	echo -e "$1" >> $LOG_FNAME
}

# Execute given command and log the command and its output
# \param $1 The command to execute
exec_logged() {
	echo -e "$1" >> $LOG_FNAME
	$1 >> $LOG_FNAME 2>&1
}

# Execute given command with given timeout
# \param $1 Timeout in seconds
# \param $2 Command to execute (surround with quotation marks)
exec_with_timeout()
{
	echo "Executing with timeout=$1: $2 ..."
	$2 &
	cmd_pid=$!
	# Setup watchdog process to kill command after timeout
	(sleep $1 && kill $cmd_pid > /dev/null 2>&1 && echo "Command timed out!") &
	killer_pid=$!
	# Wait for command completion or timeout
	wait $cmd_pid
	cmd_ret=$?
	# Kill watchdog if not timed out (i.e., command execution completed before timeout)
	kill $killer_pid > /dev/null 2>&1
	# Return actual command return code (or error of kill by timeout watchdog)
	return $cmd_ret
}

# Show progress based on given file with progress data
# $1: Progress file name (must already exist when invoked)
show_progress() {
	if [[ "$TERM" == "tester" ]]; then progress_min_interval=10 ; else progress_min_interval=1 ; fi
	local progress=0
	local prev_progress=-$progress_min_interval
	local test_done=0
	while [[ $test_done -eq 0 ]]; do
		progress=`tail -1 $1` > /dev/null 2>&1
		test_done=$? # !0 when progress file is gone (deleted by the caller who track the process state)
		progress=`echo $progress | sed 's/^0//'` # Remove leading zeros (breaks arithmetic functions)
		if [[ $test_done -eq 0 ]]; then
			if [[ $(( progress - prev_progress )) -ge $progress_min_interval ]]; then # Update only if changed by progress_min_interval
				if [[ "$TERM" == "tester" ]]; then # Special output for tester
					echo -n [${progress}%]
				else
					echo -n -e "${CSR_STAT_COLUMN}[${progress}%]${ERASE_TO_EOL}"
				fi
				prev_progress=$progress
			fi
			sleep 1
		fi
	done
}

# Execute given test and log results to stdout
# \param $1 Test name (to display)
# \param $2 Test command
# \param $3 (optional) test progress file name
exec_test() {
	progress_fname=$3
	if [[ "$TERM" != "tester" ]]; then # Interactive terminal output
		echo -n -e "$1${CSR_STAT_COLUMN}[running...]"
	else
		pad_string "$1" ${STAT_COL}
		echo -n "[running...]"
	fi
	echo ---------------------------- >> $LOG_FNAME
	echo `date`: "$1" >> $LOG_FNAME
	echo "$2" >> $LOG_FNAME

	start_seconds=$(date -u +%s)
	if [[ "$progress_fname" == "" ]]; then # no progress indication
		eval $2 >> $LOG_FNAME 2>&1
		retval=$?

	else # With progress indication
		rm -f $progress_fname # Remove old file
		eval $2 >> $LOG_FNAME 2>&1 &
		local bg_test_pid=$!
		# Wait for progress file to be created
		wait_retries=0
		retry_limit=15
		while [[ ! -f $progress_fname ]]; do
			wait_retries=$(( wait_retries + 1 ))
			if [[ $wait_retries -gt $retry_limit ]]; then
				echo Progress indication file $progress_fname is missing. Aborting.
				exit 1
			fi
			sleep 1
		done
		show_progress $progress_fname &
		show_progress_pid=$!
		wait $bg_test_pid
		test_rc=$?
		if [[ $test_rc -eq 0 ]]; then
			retval=0
		else
			retval=1
		fi
		# Stop progress display
		rm -f $progress_fname # Signals show_progress to stop
		wait $show_progress_pid
	fi

	finish_seconds=$(date -u +%s)
	elapsed_seconds=$(( finish_seconds - start_seconds ))
	elapsed_seconds=$(printf "%4ds" $elapsed_seconds)

	if [[ $retval -ne 0 ]]; then
		if [[ "$TERM" != "tester" ]]; then # Interactive terminal output
			echo -e "${CSR_STAT_COLUMN}${elapsed_seconds} ${COLOR_RED}[Failed]${COLOR_DEFAULT}${ERASE_TO_EOL}"
		else # tester
			echo "${elapsed_seconds} [Failed]"
		fi
		echo XXX Test failed XXX >> $LOG_FNAME
		TEST_FAIL_CNT=$(( TEST_FAIL_CNT + 1 ))
	else
		if [[ "$TERM" != "tester" ]]; then # Interactive terminal output
			echo -e " ${CSR_STAT_COLUMN}${elapsed_seconds} ${COLOR_GREEN}[OK]${COLOR_DEFAULT}${ERASE_TO_EOL}"
		else
			echo " ${elapsed_seconds} [OK]"
		fi
		echo VVV Test passed VVV >> $LOG_FNAME
		TEST_SUCCESS_CNT=$(( TEST_SUCCESS_CNT + 1 ))
	fi
	sync # Assure test results and log file are visible to "viewer" on PC (BuildBot)
	if [[ "$TEST_TRACE" == "1" ]]; then read -p "Press <Enter> to continue..."; fi
	return $retval
}

# Execute given test and log results to stdout
# if error code returned from test is 2, log as warning
# \param $1 Test name (to display)
# \param $2 Test command
# \param $3 (optional) test progress file name
exec_warn_test() {
	progress_fname=$3
	if [[ "$TERM" != "tester" ]]; then # Interactive terminal output
		echo -n -e "$1${CSR_STAT_COLUMN}[running...]"
	else
		pad_string "$1" ${STAT_COL}
		echo -n "[running...]"
	fi
	echo ---------------------------- >> $LOG_FNAME
	echo `date`: "$1" >> $LOG_FNAME
	echo "$2" >> $LOG_FNAME

	start_seconds=$(date -u +%s)
	if [[ "$progress_fname" == "" ]]; then # no progress indication
		eval $2 >> $LOG_FNAME 2>&1
		retval=$?

	else # With progress indication
		rm -f $progress_fname # Remove old file
		eval $2 >> $LOG_FNAME 2>&1 &
		local bg_test_pid=$!
		# Wait for progress file to be created
		wait_retries=0
		retry_limit=15
		while [[ ! -f $progress_fname ]]; do
			wait_retries=$(( wait_retries + 1 ))
			if [[ $wait_retries -gt $retry_limit ]]; then
				echo Progress indication file $progress_fname is missing. Aborting.
				exit 1
			fi
			sleep 1
		done
		show_progress $progress_fname &
		show_progress_pid=$!
		wait $bg_test_pid
		test_rc=$?
		if [[ $test_rc -eq 0 ]]; then
			retval=0
		else
			retval=1
		fi
		# Stop progress display
		rm -f $progress_fname # Signals show_progress to stop
		wait $show_progress_pid
	fi

	finish_seconds=$(date -u +%s)
	elapsed_seconds=$(( finish_seconds - start_seconds ))
	elapsed_seconds=$(printf "%4ds" $elapsed_seconds)

	if [[ $retval -ne 0 ]]; then
		if [[ "$TERM" != "tester" ]]; then # Interactive terminal output
			echo -e "${CSR_STAT_COLUMN}${elapsed_seconds} ${COLOR_RED}[Warning]${COLOR_DEFAULT}${ERASE_TO_EOL}"
		else # tester
			echo "${elapsed_seconds} [Warning]"
		fi
		echo XXX Test warning XXX >> $LOG_FNAME
		TEST_WARN_CNT=$(( TEST_WARN_CNT + 1 ))
	else
		if [[ "$TERM" != "tester" ]]; then # Interactive terminal output
			echo -e " ${CSR_STAT_COLUMN}${elapsed_seconds} ${COLOR_GREEN}[OK]${COLOR_DEFAULT}${ERASE_TO_EOL}"
		else
			echo " ${elapsed_seconds} [OK]"
		fi
		echo VVV Test passed VVV >> $LOG_FNAME
		TEST_SUCCESS_CNT=$(( TEST_SUCCESS_CNT + 1 ))
	fi
	sync # Assure test results and log file are visible to "viewer" on PC (BuildBot)
	if [[ "$TEST_TRACE" == "1" ]]; then read -p "Press <Enter> to continue..."; fi
	return $retval
}


# Execute given test and log results to stdout
# \param $1 Test name (to display)
# \param $2 Test command
# \param $3 (optional) test progress file name
exec_bad_path_test() {
	progress_fname=$3
	if [[ "$TERM" != "tester" ]]; then # Interactive terminal output
		echo -n -e "$1${CSR_STAT_COLUMN}[running...]"
	else
		pad_string "$1" ${STAT_COL}
		echo -n "[running...]"
	fi
	echo ---------------------------- >> $LOG_FNAME
	echo `date`: "$1" >> $LOG_FNAME
	echo "$2" >> $LOG_FNAME

	if [[ "$progress_fname" == "" ]]; then # no progress indication
		eval $2 >> $LOG_FNAME 2>&1
		retval=$?

	else # With progress indication
		rm -f $progress_fname # Remove old file
		eval $2 >> $LOG_FNAME 2>&1 &
		local bg_test_pid=$!
		# Wait for progress file to be created
		wait_retries=0
		retry_limit=15
		while [[ ! -f $progress_fname ]]; do
			wait_retries=$(( wait_retries + 1 ))
			if [[ $wait_retries -gt $retry_limit ]]; then
				echo Progress indication file $progress_fname is missing. Aborting.
				exit 1
			fi
			sleep 1
		done
		show_progress $progress_fname &
		show_progress_pid=$!
		wait $bg_test_pid
		test_rc=$?
		if [[ $test_rc -eq 0 ]]; then
			retval=0
		else
			retval=1
		fi
		# Stop progress display
		rm -f $progress_fname # Signals show_progress to stop
		wait $show_progress_pid
	fi

	if [[ $retval -eq 0 ]]; then
		if [[ "$TERM" != "tester" ]]; then # Interactive terminal output
			echo -e "${CSR_STAT_COLUMN}${COLOR_RED}[Failed]${COLOR_DEFAULT}${ERASE_TO_EOL}"
		else # tester
			echo "[Failed]"
		fi
		echo XXX Test failed XXX >> $LOG_FNAME
		TEST_FAIL_CNT=$(( TEST_FAIL_CNT + 1 ))
	else
		if [[ "$TERM" != "tester" ]]; then # Interactive terminal output
			echo -e "${CSR_STAT_COLUMN}${COLOR_GREEN}[OK]${COLOR_DEFAULT}${ERASE_TO_EOL}"
		else
			echo "[OK]"
		fi
		echo VVV Test passed VVV >> $LOG_FNAME
		TEST_SUCCESS_CNT=$(( TEST_SUCCESS_CNT + 1 ))
	fi
	sync # Assure test results and log file are visible to "viewer" on PC (BuildBot)
	if [[ "$TEST_TRACE" == "1" ]]; then read -p "Press <Enter> to continue..."; fi
	return $retval
}

# Execute given command in N processes simultaneously
# \param $1: Num. of processes
# \param $2: The test command. The command may include the tag <pidx> to be replaced by the process index
exec_nproc() {
	nproc=$1
	proc_idxs=`seq 0 $(( nproc - 1 ))`
	# Dispatch tests in background after replacing <pidx> tag
	for i in $proc_idxs; do
		cmd=`echo "$2" | sed 's/<pidx>/$i/g'`
		eval echo `date`: Dispatch: $cmd >> $LOG_FNAME
		eval $cmd &
		let test_pid$i=$!
	done
	# Wait for all processes to complete and check result
	nproc_fail_cnt=0
	for i in $proc_idxs; do
		wait $(( test_pid$i ))
		rc=$?
		if [[ $rc -ne 0 ]]; then
			echo Test process $i failed: rc=$rc
			nproc_fail_cnt=$(( nproc_fail_cnt + 1 ))
		fi
	done
	return $nproc_fail_cnt # Count of failures (0 on success)
}

# Same API as exec_test but only logs that test was disabled
disable_test() {
	if [[ "$TERM" != "tester" ]]; then # Interactive terminal output
		echo -e "${MODE_FAINT}$1${CSR_STAT_COLUMN}${COLOR_YELLOW}[DISABLED]${COLOR_DEFAULT}${MODE_NORMAL}"
	else
		pad_string "$1" 50
		echo "[DISABLED]"
	fi
	echo ---------------------------- >> $LOG_FNAME
	echo `date`: "$1" >> $LOG_FNAME
	echo "$2" >> $LOG_FNAME
	echo XXX Test disabled XXX >> $LOG_FNAME
	TEST_DISABLED_CNT=$(( TEST_DISABLED_CNT + 1 ))
	sync # Assure test results and log file are visible to "viewer" on PC (BuildBot)
}

# Generate test summary
gen_test_summary() {
	TEST_END_TIME=`date +%s`
	TEST_TIME=$(( TEST_END_TIME - TEST_START_TIME ))
	TEST_TIME_HR=$(( TEST_TIME / 3600 ))
	TEST_TIME_MIN=$(( ( TEST_TIME % 3600 ) / 60 ))
	TEST_TIME_SEC=$(( ( TEST_TIME % 3600 ) % 60 ))
	TEST_TIME_FMT=`printf "%02d:%02d:%02d" $TEST_TIME_HR $TEST_TIME_MIN $TEST_TIME_SEC`
	echo ============================ >> $LOG_FNAME
	echo_log "`date`: Completed tests in $TEST_TIME_FMT [hh:mm:ss]:"
	echo_log "${TAB} ${TEST_SUCCESS_CNT} succeded"
	echo_log "${TAB} ${TEST_WARN_CNT} warnins"
	echo_log "${TAB} ${TEST_FAIL_CNT} failed"
	echo_log "${TAB} ${TEST_DISABLED_CNT} temporary disabled"
	echo_log "Total: $((TEST_SUCCESS_CNT + TEST_WARN_CNT + TEST_FAIL_CNT + TEST_DISABLED_CNT)) tests."
	sync
}

get_next_test_index() {
	echo $((TEST_SUCCESS_CNT + TEST_WARN_CNT + TEST_FAIL_CNT + TEST_DISABLED_CNT))
}

# Load FW+Driver
# $1: (optional) default applet
# $2: (optional - required if $1 given) slot of default applet
# $3: (optional) dcache memory size in KB
start_driver() {
	# Map parameters to local variables
	DEFAULT_APPLET=$1
	DEFAULT_APPLET_SLOT=$2
	DCACHE_SIZE=$3

	echo "run Env Setup..."
	if [[ $LINUX_NS -eq 1 ]]; then
		exec_with_timeout 10 "./env_setup -s"
	else
		exec_with_timeout 10 ./env_setup
	fi
	if [[ $? -ne 0 ]]; then
		echo "Failed Env Setup."
		return 255
	fi

	# init_cc_app only if given default applet (i.e., skip for PE or generic-CC54 non-applet tests)
	if [[ ! -z $DEFAULT_APPLET ]]; then
		if [[ -f ./init_cc_app && -f resident.bin && -f cache.bin && -f Primary_VRL.bin ]]; then
			if [[ -z $DCACHE_SIZE ]]; then # Set default dcache size
				DCACHE_SIZE=256
			fi
			echo "Loading FW (resident + Cache+ $1@slot$2) with Dcache size set to $DCACHE_SIZE KB..."
			exec_with_timeout 10 "./init_cc_app -v Primary_VRL.bin -r resident.bin -c cache.bin -d ${DEFAULT_APPLET}_VRL.slot${DEFAULT_APPLET_SLOT}.bin ${DEFAULT_APPLET}.slot${DEFAULT_APPLET_SLOT}.bin -m $DCACHE_SIZE"
			if [[ $? -ne 0 ]]; then
				echo "Failed loading FW images."
				return 255
			fi
		else # Components required for init_cc_app of the default applet are missing
			echo "Cannot load default applet in this project!"
			echo "check for missing SeP images or missing init_cc_app."
			return 255
		fi
	fi # -z $DEFAULT_APPLET

	echo "Loading $CC_DRIVER_NAME module..."
	exec_with_timeout 10 "modprobe -v $CC_DRIVER_NAME"
	if [[ $? -ne 0 ]]; then
		echo "Failed loading driver module."
		return 254
	fi

	if [ ! -z $CC_DEV_NAME ]; then
		# Poll for udev to create device node under /dev
		rc=253 # Error if not found with 3 seconds
		for i in `seq 0 3`; do # Try for 3 seconds
			if [[ -c /dev/$CC_DEV_NAME ]]; then rc=0; break; fi
			echo Retry $i on $CC_DEV_NAME
			sleep 1
		done
		if [[ $rc -ne 0 ]]; then echo /dev/$CC_DEV_NAME not found; fi
	fi

	return $rc
}

# $1: applet name prefix
# $2: slot ID [2..15]
# $3: key index [0..2]
load_one_applet() {
	exec_with_timeout 10 "./applet_loader -app $1.slot$2.bin -vrl $1_VRL.slot$2.bin -ind $3"
	if [[ $? -ne 0 ]]; then
		echo "Failed loading applet $2."
		return 255
	fi
	return 0
}

# Load privileged applets in slots 2..5 (ind key 0); non-privileged applets in slots 6..15 (ind key 1,2)
# $1: applet name prefix
load_applets() {
	for slot in `seq 0 0`; do
                load_one_applet $1 $slot 0;
                if [[ $? -ne 0 ]]; then
                        return 255
                fi
        done
	for slot in `seq 2 5`; do
                load_one_applet $1 $slot 0;
                if [[ $? -ne 0 ]]; then
                        return 255
                fi
        done
	for slot in `seq 6 10`; do
                load_one_applet $1 $slot 1;
                if [[ $? -ne 0 ]]; then
                        return 255
                fi
        done
	for slot in `seq 11 15`; do
                load_one_applet $1 $slot 2;
        	if [[ $? -ne 0 ]]; then
        		return 255
        	fi
        done
	return 0
}

stop_driver() {
	is_driver_loaded=`lsmod| grep $CC_DRIVER_NAME | wc -l`
	if [[ $is_driver_loaded -ne 0 ]]; then
		echo "Unloading driver..."
		exec_with_timeout 10 "rmmod $CC_DRIVER_NAME"
		if [ $? -ne 0 ]; then
			echo "Failed unloading driver module $CC_DRIVER_NAME."
			return 254
		fi
	fi

	return 0
}

# Load OEM-FW image
# \param $1 Image base name (e.g., crys_demo)
load_oem_fw() {
	echo "run Env Setup..."
	exec_with_timeout 10 ./env_setup
	if [[ $? -ne 0 ]]; then
		echo "Failed Env Setup."
		return 255
	fi
	echo "Loading OEM-FW image resident-$1.bin ..."
	exec_with_timeout 10 "./init_cc_app -v ./Primary_VRL-$1.bin -r ./resident-$1.bin"
	if [[ $? -ne 0 ]]; then
		echo "Failed loading $1 FW image."
		return 255
	fi
	return 0
}

