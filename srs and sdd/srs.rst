:Author: Oleh Chernygevych <oleh.chernygevych@gmail.com>

Console sniffer application for network traffic analysis
=====================================================================

Table of contents
-----------------
**1) Introduction**
  | Product overview
  | Purpose
  | Definitions
  | Project scope
  
**2) Functional requirements**

**3) Non-functional requirements**
  | Operating environment
  
**4) Graphical user interface requirements**
  | General requirements
  | GUI structure

1) Introduction
============

Product overview
----------------
| This network sniffer application analyze(decodes) incoming network packets
| and log information about them into a text file. 
| User can set file for logging and set filter by protocol. 
| Application supports IPv4 and IPv6 stacks.

Purpose
-------
| The purpose of this document is to describe basic mechanisms and provide a
| detailed description of the functional and non-functional requirements of 
| the sniffer application.

Definitions
-----------
Sniffer
 | Packet sniffer (packet analyzer, network analyzer) is a program 
 | that can intercept netwrok traffic and log information about packets 
 | passing over the network.
.txt
 | .txt is a file format for files consisting of text usually containing 
 | very little formatting.
GUI
 | Graphical User Interface
Network protocol, protocol
 | network protocol, or just protocol, is a system of digital rules for data
 | exchange within or between computers.
 
Project scope
-------------
| The sniffer is an application that can 
| run on Windows and Linux desktop systems. 

2) Functional requirements
=======================

**Ability to start/stop logging.**
  | User can stop intercepting packets and log information about them 
  | using console menu. While sniffer is intercepting packets counters
  | for protocols are shown on the console. 
  | To stop logging user must use the defined keyboard keys combination, 
  | that is also shown on his console.

**User can set file for logging.**
  | Using console interface user can set file for logging information 
  | about intercepted packets. User inputs a file name and the application
  | creates a file in .txt extension in it's root directory. If a file with
  | the same name and extension already exists the application will overwrite it.
  | If user don't use this option then the standard file named "log.txt" will
  | be used.

**User can add filtering by a protocol.**
  | Using console menu user can set filtering by a protocol. 
  | Console shows user which protocols it can intercept and user can choose 
  | which protocols must be excluded from logging.

3) Non-functional requirements
===========================

Operating environment
---------------------
| This section describes some specific software and hardware requirements:

- A network interface controller (to analyze traffic not only within 
  the host computer)
- Desktop versions of Linux and Windows. 
- Administrator privileges may be needed on both systems.

4) Graphical user interface requirements
===========================================

General requirements
--------------------
- Console interface
- Uses standard colour scheme + green and red colours

GUI structure
-------------
The following is a representation of the main console menu:
::

   1) start network sniffing
   2) set filter
   3) set logging_file
   4) exit

**1) Start network sniffing**

| Starts network sniffing. If file for logging is not set by the user 
| the application will use the standard file named "log.txt".

**2) Set filter**

| Prints a numeric list of protocols on the console in red
| or green colours. Red colour means that the protocol will not be analyzed.
| The protocols coloured green will be analyzed. By inputting protocol's number
| the user can turn on/off the protocol in the filter.

**3) Set logging file**

| Allows user to input a name for the file he/she wants to be used for logging.
  