SNMP-Programming
================

There are three functions in my program.

1.	void create_interface_table(netsnmp_session *ss)
-	get the ipAdEntIfIndex object for interface index
-	get the ipAdEntAddr object for the related ipaddress
	
2.	void create_ip_neighbour_table(netsnmp_session *ss)

-	get the ipNetToMediaIfIndex object for interface index
-	get the ipNetToMediaNetAddress object to show all neighbor ip for each interface


3.	void create_traffic_data(netsnmp_session *ss)
-	get the ifIndex object for interface index
-	get the ifOutOctets object to show the traffic

In these functions, I use multiple times of “SNMP_MSG_GETNEXT” to get all instances for each object that is similar the function of snmpwalk. And Finally, print out the instances.
