#!/bin/bash
#
# Spread out (hard-coded) shell jobs on a multi-core cpu. See e() for the beef
# Wolfgang Woehl 11/2010
#
# Based on Martin Christoph's http://www.da7a.de/linux/bash-parallelverarbeitung
# 
# Usage:   threads-test.bash <list of files>
# Example: threads-test.bash tiffs/*

# set THREADS to a number that makes sense (8 is a good starting point on a quad core)
THREADS=8
# list carries the provided shell arguments, usually a list of files
list=( "$@" )
# each shell argument (file) will be processed as 1 task
TASKS=${#list[*]}

# execution function
e()
{
  # ${2} -> second argument of the e() call -> task number. you gotta love bash syntax ...
  file=${list[${2}]}
  echo "thread: ${1} (${SECONDS}s) -> execute task ${2} -> $(basename ${file})"
  #
  # define the processing you want to execute for each shell argument here
  # with these examples output ends up in the current directory
  image_to_j2k -cinema2K 24 -i ${file} -o $(basename ${file}).j2c > /dev/null 2>&1
  #kdu_compress -i ${file} -o $(basename ${file}).j2c Sprofile=CINEMA2K Creslengths=1302083 Creslengths:C0=1302083,1041666 Creslengths:C1=1302083,1041666 Creslengths:C2=1302083,1041666 > /dev/null 2>&1
  #
}
 
# thread function will be called (and backgrounded) THREADS times
# TASKS will be split up between the available "threads" (jobs, rather)
t()
{
  thread_id=$1
  echo "t:${thread_id} (${SECONDS}s) started"
  a=0
  while [[ ${a} -lt ${TASKS} ]]; do
    b=$(( ${a} % ${THREADS} ))
    if [[ ${b} = ${thread_id} ]]; then
      e ${thread_id} ${a}
    fi
  index=$(( ${index} + 1 ))
  a=$(( ${a} + 1 ))
  done
  echo "t:${thread_id} (${SECONDS}s) done"
}
 
# run threads
i=0
while [[ ${i} -lt ${THREADS} ]]; do
    t ${i} &
    i=$(( ${i} + 1 ))
done
 
# wait until all threads are done
wait
 
echo "${TASKS} tasks done (${SECONDS}s)"

