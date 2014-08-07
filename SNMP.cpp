/*
	Author: Ho Yin Cheng
	SNMP Project
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <string.h>


void create_interface_table(netsnmp_session *ss);		
void create_ip_neighbour_table(netsnmp_session *ss);
void create_traffic_data(netsnmp_session *ss);


int main(int argc, char ** argv)
{
	netsnmp_session session, *ss;
	int samples = 0;
	int count = 0;
	int millisecond = 0;
	char host[30];
	char community[30];


	printf("Please input Host Name or Ip:\n");
	scanf("%s", host);
	printf("\n");
	
	printf("Please input the community name:\n");
	scanf("%s", community);
	printf("\n");
	
	printf("Please input the time interval in seconds:\n");
	scanf("%d", &millisecond);
	millisecond = 100 * millisecond;
	printf("\n");

	printf("Please input the total number of samples:\n");
	scanf("%d", &samples);
	printf("\n");

	millisecond = samples*millisecond;




	/*
	* Initialize the SNMP library
	*/
	init_snmp("snmpdemoapp");

	/*
	* Initialize a "session" that defines who we're going to talk to
	*/
	snmp_sess_init(&session);                   /* set up defaults */
	session.peername = strdup(host);

	/* set up the authentication parameters for talking to the server */



	/* set the SNMP version number */
	session.version = SNMP_VERSION_1;

	/* set the SNMPv1 community name used for authentication */
	session.community = community;
	session.community_len = strlen(session.community);



	/*
	* Open the session
	*/
	SOCK_STARTUP;
	ss = snmp_open(&session);                     /* establish the session */

	if (!ss) {
		snmp_sess_perror("ack", &session);
		SOCK_CLEANUP;
		exit(1);
	}
	printf("\n\n\n");
	create_interface_table(ss);
	printf("\n\n\n");
	create_ip_neighbour_table(ss);
	
	
	printf("Traffic:	\n");
	for (count = 0; count < samples; count++)
	{
		
		printf("%d .   \n", count + 1);
		create_traffic_data(ss);
		printf("\n\n\n");

		Sleep(millisecond);			//sleep a period and get the information again
	}


	snmp_close(ss);

	SOCK_CLEANUP;

	

	return (0);
} /* main() */


void create_interface_table(netsnmp_session *ss)
{
	netsnmp_pdu    *pdu, *response;
	netsnmp_variable_list *vars,  obj_vars;
	int             status;
	u_char		   *tmp_data;
	int rowsize = 0;
	int i = 0;
	int j = 0;
	int going = 1;
	oid             name[MAX_OID_LEN];
	size_t          name_length;
	static oid      root[MAX_OID_LEN];	
	static size_t   rootlen;


	rootlen = MAX_OID_LEN;
	if (!snmp_parse_oid("IP-MIB::ipAdEntIfIndex", root, &rootlen)) {
		snmp_perror("IP-MIB::ipAdEntIfIndex");
		SOCK_CLEANUP;
		exit(1);
	}
	memmove(name, root, rootlen * sizeof(oid));	//save the starting point
	name_length = rootlen;


	while (going)
	{
		pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);			//create message
		snmp_add_null_var(pdu, name, name_length);			//sednd
		status = snmp_synch_response(ss, pdu, &response);	//wait respind

		//find the row size first then collect data
		if (status == STAT_SUCCESS&& response->errstat == SNMP_ERR_NOERROR)
		{
			for (vars = response->variables; vars; vars = vars->next_variable)
			{
				if ((vars->name_length < rootlen) || (memcmp(root, vars->name, rootlen * sizeof(oid)) != 0))
				{
					/*
					* not part of this column data
					*/
					going = 0;
					continue;
				}
				rowsize++;
				memmove((char *)name, (char *)vars->name, vars->name_length * sizeof(oid));
				name_length = vars->name_length;
			}
		}
		else
		{
			/*
			* FAILURE: print what went wrong!
			*/
			if (status == STAT_SUCCESS)
			{
				fprintf(stderr, "Error in packet\nReason: %s\n",
					snmp_errstring(response->errstat));
			}

			else if (status == STAT_TIMEOUT)
			{
				netsnmp_session tmp_session = *ss;
				fprintf(stderr, "Timeout: No response from %s.\n",
					tmp_session.peername);
			}
			else
			{
				snmp_sess_perror("snmpdemoapp", ss);
			}

		}
		
	}
	
	
	
	//we got the row size, collect data
	memmove(name, root, rootlen * sizeof(oid));
	name_length = rootlen;
	netsnmp_variable_list *tmptable = malloc(rowsize * 2 * sizeof(netsnmp_variable_list));			//create an array to save data
	going = 1;
	i = 0;

	while (going)
	{

		pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
		snmp_add_null_var(pdu, name, name_length);
		status = snmp_synch_response(ss, pdu, &response);

		//find the row size first then collect data
		if (status == STAT_SUCCESS&& response->errstat == SNMP_ERR_NOERROR)
		{
			for (vars = response->variables; vars; vars = vars->next_variable)
			{
				if ((vars->name_length < rootlen) || (memcmp(root, vars->name, rootlen * sizeof(oid)) != 0))
				{
					/*
					* not part of this column data
					*/
					going = 0;
					continue;
				}
				obj_vars = *vars;
				*(tmptable + i) = obj_vars;//save data
				i = i + 2;

				memmove((char *)name, (char *)vars->name, vars->name_length * sizeof(oid));
				name_length = vars->name_length;
			}
		}
		else
		{
			/*
			* FAILURE: print what went wrong!
			*/
			if (status == STAT_SUCCESS)
			{
				fprintf(stderr, "Error in packet\nReason: %s\n",
					snmp_errstring(response->errstat));
			}

			else if (status == STAT_TIMEOUT)
			{
				netsnmp_session tmp_session = *ss;
				fprintf(stderr, "Timeout: No response from %s.\n",
					tmp_session.peername);
			}
			else
			{
				snmp_sess_perror("snmpdemoapp", ss);
			}
		}

	}

	going = 1;												//reset the variable
	i = 1;
	if (!snmp_parse_oid("IP-MIB::ipAdEntAddr", root, &rootlen))			
	{
		snmp_perror("IP-MIB::ipAdEntAddr");
		SOCK_CLEANUP;
		exit(1);
	}
	memmove(name, root, rootlen * sizeof(oid));
	name_length = rootlen;

	while (going)
	{
		pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
		snmp_add_null_var(pdu, name, name_length);
		status = snmp_synch_response(ss, pdu, &response);
		if (status == STAT_SUCCESS&& response->errstat == SNMP_ERR_NOERROR)
		{
			for (vars = response->variables; vars; vars = vars->next_variable)
			{
				if ((vars->name_length < rootlen) || (memcmp(root, vars->name, rootlen * sizeof(oid)) != 0))
				{
					/*
					* not part of this column data
					*/
					going = 0;
					continue;
				}
				obj_vars = *vars;
				*(tmptable + i) = obj_vars;//save data
				i = i + 2;
				memmove((char *)name, (char *)vars->name, vars->name_length * sizeof(oid));
				name_length = vars->name_length;
			}
		}
		else
		{
			/*
			* FAILURE: print what went wrong!
			*/
			if (status == STAT_SUCCESS)
			{
				fprintf(stderr, "Error in packet\nReason: %s\n",
					snmp_errstring(response->errstat));
			}

			else if (status == STAT_TIMEOUT)
			{
				netsnmp_session tmp_session = *ss;
				fprintf(stderr, "Timeout: No response from %s.\n",
					tmp_session.peername);
			}
			else
			{
				snmp_sess_perror("snmpdemoapp", ss);
			}
		}
	}



		printf("Interface Index  and IP Address                   \n");
		printf("----------------------------------------------------------------------------\n");

		for (i = 0; i < rowsize * 2; i++)
		{

			vars = (tmptable +i);
			print_value(vars->name, vars->name_length, vars);
			//printf("            ");
			if (i % 2)
			{
				printf("\n");
			}

		}
		/*
		* Clean up:
		*  1) free the response.
		*  2) close the session.
		*/
		if (response)
			snmp_free_pdu(response);

}


void create_ip_neighbour_table(netsnmp_session *ss)		//identical, just the mib object change
{
	netsnmp_pdu    *pdu, *response;
	netsnmp_variable_list *vars, obj_vars;
	int             status;
	u_char		   *tmp_data;
	int rowsize = 0;
	int i = 0;
	int j = 0;
	int going = 1;
	oid             name[MAX_OID_LEN];
	size_t          name_length;
	static oid      root[MAX_OID_LEN];
	static size_t   rootlen;


	rootlen = MAX_OID_LEN;
	if (!snmp_parse_oid("IP-MIB::ipNetToMediaIfIndex", root, &rootlen)) {
		snmp_perror("IP-MIB::ipNetToMediaIfIndex");
		SOCK_CLEANUP;
		exit(1);
	}
	memmove(name, root, rootlen * sizeof(oid));	//save the starting point
	name_length = rootlen;


	while (going)
	{
		pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
		snmp_add_null_var(pdu, name, name_length);
		status = snmp_synch_response(ss, pdu, &response);

		//find the row size first then collect data
		if (status == STAT_SUCCESS&& response->errstat == SNMP_ERR_NOERROR)
		{
			for (vars = response->variables; vars; vars = vars->next_variable)
			{
				if ((vars->name_length < rootlen) || (memcmp(root, vars->name, rootlen * sizeof(oid)) != 0))
				{
					/*
					* not part of this column data
					*/
					going = 0;
					continue;
				}
				rowsize++;
				memmove((char *)name, (char *)vars->name, vars->name_length * sizeof(oid));
				name_length = vars->name_length;
			}


		}
		else
		{
			/*
			* FAILURE: print what went wrong!
			*/
			if (status == STAT_SUCCESS)
			{
				fprintf(stderr, "Error in packet\nReason: %s\n",
					snmp_errstring(response->errstat));
			}

			else if (status == STAT_TIMEOUT)
			{
				netsnmp_session tmp_session = *ss;
				fprintf(stderr, "Timeout: No response from %s.\n",
					tmp_session.peername);
			}
			else
			{
				snmp_sess_perror("snmpdemoapp", ss);
			}

		}

	}
	//we got the row size, collect data
	memmove(name, root, rootlen * sizeof(oid));
	name_length = rootlen;
	netsnmp_variable_list *tmptable = malloc(rowsize * 2 * sizeof(netsnmp_variable_list));
	going = 1;
	i = 0;

	while (going)
	{
		pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
		snmp_add_null_var(pdu, name, name_length);
		status = snmp_synch_response(ss, pdu, &response);

		//find the row size first then collect data
		if (status == STAT_SUCCESS&& response->errstat == SNMP_ERR_NOERROR)
		{
			for (vars = response->variables; vars; vars = vars->next_variable)
			{
				if ((vars->name_length < rootlen) || (memcmp(root, vars->name, rootlen * sizeof(oid)) != 0))
				{
					/*
					* not part of this column data
					*/
					going = 0;
					continue;
				}
				obj_vars = *vars;
				*(tmptable + i) = obj_vars;//save data
				i = i + 2;

				memmove((char *)name, (char *)vars->name, vars->name_length * sizeof(oid));
				name_length = vars->name_length;
			}
		}
		else
		{
			/*
			* FAILURE: print what went wrong!
			*/
			if (status == STAT_SUCCESS)
			{
				fprintf(stderr, "Error in packet\nReason: %s\n",
					snmp_errstring(response->errstat));
			}

			else if (status == STAT_TIMEOUT)
			{
				netsnmp_session tmp_session = *ss;
				fprintf(stderr, "Timeout: No response from %s.\n",
					tmp_session.peername);
			}
			else
			{
				snmp_sess_perror("snmpdemoapp", ss);
			}
		}

	}

	going = 1;
	i = 1;
	if (!snmp_parse_oid("IP-MIB::ipNetToMediaNetAddress", root, &rootlen)) {
		snmp_perror("IP-MIB::ipNetToMediaNetAddress");
		SOCK_CLEANUP;
		exit(1);
	}
	memmove(name, root, rootlen * sizeof(oid));
	name_length = rootlen;

	while (going)
	{
		pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
		snmp_add_null_var(pdu, name, name_length);
		status = snmp_synch_response(ss, pdu, &response);
		if (status == STAT_SUCCESS&& response->errstat == SNMP_ERR_NOERROR)
		{
			for (vars = response->variables; vars; vars = vars->next_variable)
			{
				if ((vars->name_length < rootlen) || (memcmp(root, vars->name, rootlen * sizeof(oid)) != 0))
				{
					/*
					* not part of this column data
					*/
					going = 0;
					continue;
				}
				obj_vars = *vars;
				*(tmptable + i) = obj_vars;//save data
				i = i + 2;
				memmove((char *)name, (char *)vars->name, vars->name_length * sizeof(oid));
				name_length = vars->name_length;
			}
		}
		else
		{
			/*
			* FAILURE: print what went wrong!
			*/
			if (status == STAT_SUCCESS)
			{
				fprintf(stderr, "Error in packet\nReason: %s\n",
					snmp_errstring(response->errstat));
			}

			else if (status == STAT_TIMEOUT)
			{
				netsnmp_session tmp_session = *ss;
				fprintf(stderr, "Timeout: No response from %s.\n",
					tmp_session.peername);
			}
			else
			{
				snmp_sess_perror("snmpdemoapp", ss);
			}
		}
	}



	printf("Interface Index  and Neighbour IP                   \n");
	printf("----------------------------------------------------------------------------\n");

	for (i = 0; i < rowsize * 2; i++)
	{

		vars = (tmptable + i);
		print_value(vars->name, vars->name_length, vars);
		//printf("            ");
		if (i % 2)
		{
			printf("\n");
		}

	}
	/*
	* Clean up:
	*  1) free the response.
	*  2) close the session.
	*/
	if (response)
		snmp_free_pdu(response);


}
void create_traffic_data(netsnmp_session *ss)			//identical, just the mib object change
{
	netsnmp_pdu    *pdu, *response;
	netsnmp_variable_list *vars, obj_vars;
	int             status;
	u_char		   *tmp_data;
	int rowsize = 0;
	int i = 0;
	int j = 0;
	int going = 1;
	oid             name[MAX_OID_LEN];
	size_t          name_length;
	static oid      root[MAX_OID_LEN];
	static size_t   rootlen;


	rootlen = MAX_OID_LEN;
	if (!snmp_parse_oid("IF-MIB::ifIndex", root, &rootlen)) {
		snmp_perror("IP-MIB::ifIndex");
		SOCK_CLEANUP;
		exit(1);
	}
	memmove(name, root, rootlen * sizeof(oid));	//save the starting point
	name_length = rootlen;


	while (going)
	{
		pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
		snmp_add_null_var(pdu, name, name_length);
		status = snmp_synch_response(ss, pdu, &response);

		//find the row size first then collect data
		if (status == STAT_SUCCESS&& response->errstat == SNMP_ERR_NOERROR)
		{
			for (vars = response->variables; vars; vars = vars->next_variable)
			{
				if ((vars->name_length < rootlen) || (memcmp(root, vars->name, rootlen * sizeof(oid)) != 0))
				{
					/*
					* not part of this column data
					*/
					going = 0;
					continue;
				}
				rowsize++;
				memmove((char *)name, (char *)vars->name, vars->name_length * sizeof(oid));
				name_length = vars->name_length;
			}


		}
		else
		{
			/*
			* FAILURE: print what went wrong!
			*/
			if (status == STAT_SUCCESS)
			{
				fprintf(stderr, "Error in packet\nReason: %s\n",
					snmp_errstring(response->errstat));
			}

			else if (status == STAT_TIMEOUT)
			{
				netsnmp_session tmp_session = *ss;
				fprintf(stderr, "Timeout: No response from %s.\n",
					tmp_session.peername);
			}
			else
			{
				snmp_sess_perror("snmpdemoapp", ss);
			}

		}

	}
	//we got the row size, collect data
	memmove(name, root, rootlen * sizeof(oid));
	name_length = rootlen;
	netsnmp_variable_list *tmptable = malloc(rowsize * 2 * sizeof(netsnmp_variable_list));
	going = 1;
	i = 0;

	while (going)
	{
		pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
		snmp_add_null_var(pdu, name, name_length);
		status = snmp_synch_response(ss, pdu, &response);

		//find the row size first then collect data
		if (status == STAT_SUCCESS&& response->errstat == SNMP_ERR_NOERROR)
		{
			for (vars = response->variables; vars; vars = vars->next_variable)
			{
				if ((vars->name_length < rootlen) || (memcmp(root, vars->name, rootlen * sizeof(oid)) != 0))
				{
					/*
					* not part of this column data
					*/
					going = 0;
					continue;
				}
				obj_vars = *vars;
				*(tmptable + i) = obj_vars;//save data
				i = i + 2;

				memmove((char *)name, (char *)vars->name, vars->name_length * sizeof(oid));
				name_length = vars->name_length;
			}
		}
		else
		{
			/*
			* FAILURE: print what went wrong!
			*/
			if (status == STAT_SUCCESS)
			{
				fprintf(stderr, "Error in packet\nReason: %s\n",
					snmp_errstring(response->errstat));
			}

			else if (status == STAT_TIMEOUT)
			{
				netsnmp_session tmp_session = *ss;
				fprintf(stderr, "Timeout: No response from %s.\n",
					tmp_session.peername);
			}
			else
			{
				snmp_sess_perror("snmpdemoapp", ss);
			}
		}

	}

	going = 1;
	i = 1;
	if (!snmp_parse_oid("IF-MIB::ifOutOctets", root, &rootlen)) {
		snmp_perror("IF-MIB::ifOutOctets");
		SOCK_CLEANUP;
		exit(1);
	}
	memmove(name, root, rootlen * sizeof(oid));
	name_length = rootlen;

	while (going)
	{
		pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
		snmp_add_null_var(pdu, name, name_length);
		status = snmp_synch_response(ss, pdu, &response);
		if (status == STAT_SUCCESS&& response->errstat == SNMP_ERR_NOERROR)
		{
			for (vars = response->variables; vars; vars = vars->next_variable)
			{
				if ((vars->name_length < rootlen) || (memcmp(root, vars->name, rootlen * sizeof(oid)) != 0))
				{
					/*
					* not part of this column data
					*/
					going = 0;
					continue;
				}
				obj_vars = *vars;
				*(tmptable + i) = obj_vars;//save data
				i = i + 2;
				memmove((char *)name, (char *)vars->name, vars->name_length * sizeof(oid));
				name_length = vars->name_length;
			}
		}
		else
		{
			/*
			* FAILURE: print what went wrong!
			*/
			if (status == STAT_SUCCESS)
			{
				fprintf(stderr, "Error in packet\nReason: %s\n",
					snmp_errstring(response->errstat));
			}

			else if (status == STAT_TIMEOUT)
			{
				netsnmp_session tmp_session = *ss;
				fprintf(stderr, "Timeout: No response from %s.\n",
					tmp_session.peername);
			}
			else
			{
				snmp_sess_perror("snmpdemoapp", ss);
			}
		}
	}



	printf("Interface Index  and Traffic(ifOutOctets)                  \n");
	printf("----------------------------------------------------------------------------\n");

	for (i = 0; i < rowsize * 2; i++)
	{

		vars = (tmptable + i);
		print_value(vars->name, vars->name_length, vars);
		//printf("            ");
		if (i % 2)
		{
			printf("\n");
		}

	}
	/*
	* Clean up:
	*  1) free the response.
	*  2) close the session.
	*/
	if (response)
		snmp_free_pdu(response);










}




	
	

	




		
			

	

		




















