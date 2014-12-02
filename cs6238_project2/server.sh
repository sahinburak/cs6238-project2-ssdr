#!/bin/bash

#Compiling codes
echo 'Compiling Source Codes'
javac -g -sourcepath src/ -d bin/ -cp .:bin src/*.java

#Executing codes
echo ''
echo 'Starting SDDR Server'
java -cp bin Server
