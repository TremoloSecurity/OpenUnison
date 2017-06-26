#!/bin/bash

# Copyright 2017 Tremolo Security, Inc.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


if [ "$#" -ne 4 ]; then
    echo "Four arguments must be passed: path_to_openunison_war path_to_openunison_configuration_yaml path_to_deploy_to path_to_quartz_directory"
    exit 1
fi

echo "Path to war : $1"
echo "Path to configuration : $2"
echo "Path to deployment : $3"
echo "Path to quartz configuration : $4"

#Need to add some error checking

export pid="$(cat $3/.pid)"

if ps -p $pid > /dev/null
then
   echo "OpenUnison on Undertow is running on $pid, stop OpenUnison first"
   exit 0
fi

if [ -z $3 ]; then
	echo "path to deployment not set, exiting"
	exit 1
fi

mkdir -p $4

echo "Clearing $3"
rm -rf $3

echo "Creating $3"
mkdir -p $3/webapp
cp $1 $3/webapp/
cd $3/webapp
unzip $(ls *.war) > /dev/null

rm -f $3/webapp/*.war
mv $3/webapp/WEB-INF/lib $3/
mv $3/webapp/WEB-INF/classes $3/
mkdir $3/logs

export CLASSPATH="$3/lib/*:$3/classes:$4"
echo $CLASSPATH
exec java -classpath $CLASSPATH $JAVA_OPTS com.tremolosecurity.openunison.undertow.OpenUnisonOnUndertow $2 >> $3/logs/openunison.log 2>&1 &
echo $! > $3/.pid