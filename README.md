# UDR-Interface-Swap
Powershell Script to modify the next hop for route tables.   Provides HA failover for PANW firewalls

The script runs as an Azure function either within your private VPC (App Service Plan) or on Azure hosted services outside your VNET.

The script will monitor either the "running" state of the Paloaltonetworks firewalls or perform path monitoring via TCP probes to determine the health of the firewalls. 

If a fault is detected the script performs the following 

1) Builds an array of interface addresses of the primary and secondary firewalls.   IF new interfaces are added then the script will detect these new interfaces automatically

2) Finds all the route tables within the subscriptions configured as variables in the file.

3) Finds all routing entries in the routing tables and if a route entry matches an inteface in the failed firewall it will update the route table entry to reference the backup firewall interface. 

Total update times vary as the script will update the routing tables sequentially.  Update times for each route table are approximately 20 seconds.



Todo:::::

A useful modification would be to run the table updates asynchronously to reduce failover times. 

