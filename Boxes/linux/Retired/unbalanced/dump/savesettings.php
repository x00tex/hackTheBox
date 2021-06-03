<?php
/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

if(basename($_SERVER['SCRIPT_FILENAME']) !== "settings.php")
{
	die("Direct access to this script is forbidden!");
}

function validIP($address){
	if (preg_match('/[.:0]/', $address) && !preg_match('/[1-9a-f]/', $address)) {
		// Test if address contains either `:` or `0` but not 1-9 or a-f
		return false;
	}
	return !filter_var($address, FILTER_VALIDATE_IP) === false;
}

// Check for existance of variable
// and test it only if it exists
function istrue(&$argument) {
	if(isset($argument))
	{
		if($argument)
		{
			return true;
		}
	}
	return false;
}

// Credit: http://stackoverflow.com/a/4694816/2087442
function validDomain($domain_name)
{
	$validChars = preg_match("/^([_a-z\d](-*[_a-z\d])*)(\.([_a-z\d](-*[a-z\d])*))*(\.([a-z\d])*)*$/i", $domain_name);
	$lengthCheck = preg_match("/^.{1,253}$/", $domain_name);
	$labelLengthCheck = preg_match("/^[^\.]{1,63}(\.[^\.]{1,63})*$/", $domain_name);
	return ( $validChars && $lengthCheck && $labelLengthCheck ); //length of each label
}

function validDomainWildcard($domain_name)
{
	// There has to be either no or at most one "*" at the beginning of a line
	$validChars = preg_match("/^((\*.)?[_a-z\d](-*[_a-z\d])*)(\.([_a-z\d](-*[a-z\d])*))*(\.([a-z\d])*)*$/i", $domain_name);
	$lengthCheck = preg_match("/^.{1,253}$/", $domain_name);
	$labelLengthCheck = preg_match("/^[^\.]{1,63}(\.[^\.]{1,63})*$/", $domain_name);
	return ( $validChars && $lengthCheck && $labelLengthCheck ); //length of each label
}

function validMAC($mac_addr)
{
  // Accepted input format: 00:01:02:1A:5F:FF (characters may be lower case)
  return (preg_match('/([a-fA-F0-9]{2}[:]?){6}/', $mac_addr) == 1);
}

$dhcp_static_leases = array();
function readStaticLeasesFile()
{
	global $dhcp_static_leases;
	$dhcp_static_leases = array();
	try
	{
		$dhcpstatic = @fopen('/etc/dnsmasq.d/04-pihole-static-dhcp.conf', 'r');
	}
	catch(Exception $e)
	{
		echo "Warning: Failed to read /etc/dnsmasq.d/04-pihole-static-dhcp.conf, this is not an error";
		return false;
	}

	if(!is_resource($dhcpstatic))
		return false;

	while(!feof($dhcpstatic))
	{
		// Remove any possibly existing variable with this name
		$mac = ""; $one = ""; $two = "";
		sscanf(trim(fgets($dhcpstatic)),"dhcp-host=%[^,],%[^,],%[^,]",$mac,$one,$two);
		if(strlen($mac) > 0 && validMAC($mac))
		{
			if(validIP($one) && strlen($two) == 0)
				// dhcp-host=mac,IP - no HOST
				array_push($dhcp_static_leases,["hwaddr"=>$mac, "IP"=>$one, "host"=>""]);
			elseif(strlen($two) == 0)
				// dhcp-host=mac,hostname - no IP
				array_push($dhcp_static_leases,["hwaddr"=>$mac, "IP"=>"", "host"=>$one]);
			else
				// dhcp-host=mac,IP,hostname
				array_push($dhcp_static_leases,["hwaddr"=>$mac, "IP"=>$one, "host"=>$two]);
		}
		else if(validIP($one) && validDomain($mac))
		{
			// dhcp-host=hostname,IP - no MAC
			array_push($dhcp_static_leases,["hwaddr"=>"", "IP"=>$one, "host"=>$mac]);
		}
	}
	return true;
}

function isequal(&$argument, &$compareto) {
	if(isset($argument))
	{
		if($argument === $compareto)
		{
			return true;
		}
	}
	return false;
}

function isinserverlist($addr) {
	global $DNSserverslist;
	foreach ($DNSserverslist as $key => $value) {
		if (isequal($value['v4_1'],$addr) || isequal($value['v4_2'],$addr))
			return true;
		if (isequal($value['v6_1'],$addr) || isequal($value['v6_2'],$addr))
			return true;
	}
	return false;
}

$DNSserverslist = [];
function readDNSserversList()
{
	// Reset list
	$list = [];
	$handle = @fopen("/etc/pihole/dns-servers.conf", "r");
	if ($handle)
	{
		while (($line = fgets($handle)) !== false)
		{
			$line = rtrim($line);
			$line = explode(';', $line);
			$name = $line[0];
			$values = [];
			if (!empty($line[1])) {
				$values["v4_1"] = $line[1];
			}
			if (!empty($line[2])) {
				$values["v4_2"] = $line[2];
			}
			if (!empty($line[3])) {
				$values["v6_1"] = $line[3];
			}
			if (!empty($line[4])) {
				$values["v6_2"] = $line[4];
			}
            $list[$name] = $values;
		}
		fclose($handle);
	}
	return $list;
}

$adlist = [];
function readAdlists()
{
	// Reset list
	$list = [];
	$handle = @fopen("/etc/pihole/adlists.list", "r");
	if ($handle)
	{
		while (($line = fgets($handle)) !== false)
		{
			if(strlen($line) < 3)
			{
				continue;
			}
			elseif($line[0] === "#")
			{
				// Comments start either with "##" or "# "
				if($line[1] !== "#" &&
				   $line[1] !== " ")
				{
					// Commented list
					array_push($list, [false,rtrim(substr($line, 1))]);
				}
			}
			else
			{
				// Active list
				array_push($list, [true,rtrim($line)]);
			}
		}
		fclose($handle);
	}
	return $list;
}

	// Read available adlists
	$adlist = readAdlists();
	// Read available DNS server list
	$DNSserverslist = readDNSserversList();

	$error = "";
	$success = "";

	if(isset($_POST["field"]))
	{
		// Handle CSRF
		check_csrf(isset($_POST["token"]) ? $_POST["token"] : "");

		// Process request
		switch ($_POST["field"]) {
			// Set DNS server
			case "DNS":

				$DNSservers = [];
				// Add selected predefined servers to list
				foreach ($DNSserverslist as $key => $value)
				{
					foreach(["v4_1", "v4_2", "v6_1", "v6_2"] as $type)
					{
						if(@array_key_exists("DNSserver".str_replace(".","_",$value[$type]),$_POST))
						{
							array_push($DNSservers,$value[$type]);
						}
					}
				}

				// Test custom server fields
				for($i=1;$i<=4;$i++)
				{
					if(array_key_exists("custom".$i,$_POST))
					{
						$exploded = explode("#", $_POST["custom".$i."val"], 2);
						$IP = $exploded[0];
						if(count($exploded) > 1)
						{
							$port = $exploded[1];
						}
						else
						{
							$port = "53";
						}
						if(!validIP($IP))
						{
							$error .= "IP (".htmlspecialchars($IP).") is invalid!<br>";
						}
						elseif(!is_numeric($port))
						{
							$error .= "Port (".htmlspecialchars($port).") is invalid!<br>";
						}
						else
						{
							array_push($DNSservers,$IP."#".$port);
						}
					}
				}
				$DNSservercount = count($DNSservers);

				// Check if at least one DNS server has been added
				if($DNSservercount < 1)
				{
					$error .= "No DNS server has been selected.<br>";
				}

				// Check if domain-needed is requested
				if(isset($_POST["DNSrequiresFQDN"]))
				{
					$extra = "domain-needed ";
				}
				else
				{
					$extra = "domain-not-needed ";
				}

				// Check if domain-needed is requested
				if(isset($_POST["DNSbogusPriv"]))
				{
					$extra .= "bogus-priv ";
				}
				else
				{
					$extra .= "no-bogus-priv ";
				}

				// Check if DNSSEC is requested
				if(isset($_POST["DNSSEC"]))
				{
					$extra .= "dnssec";
				}
				else
				{
					$extra .= "no-dnssec";
				}

				// Check if Conditional Forwarding is requested
				if(isset($_POST["conditionalForwarding"]))
				{
					// Validate conditional forwarding IP
					if (!validIP($_POST["conditionalForwardingIP"]))
					{
						$error .= "Conditional forwarding IP (".htmlspecialchars($_POST["conditionalForwardingIP"]).") is invalid!<br>";
					}

					// Validate conditional forwarding domain name
					if(!validDomain($_POST["conditionalForwardingDomain"]))
					{
						$error .= "Conditional forwarding domain name (".htmlspecialchars($_POST["conditionalForwardingDomain"]).") is invalid!<br>";
					}
					if(!$error)
					{
						$addressArray = explode(".", $_POST["conditionalForwardingIP"]);
						$reverseAddress = $addressArray[2].".".$addressArray[1].".".$addressArray[0].".in-addr.arpa";
						$extra .= " conditional_forwarding ".$_POST["conditionalForwardingIP"]." ".$_POST["conditionalForwardingDomain"]." $reverseAddress";
					}
				}

				// Check if DNSinterface is set
				if(isset($_POST["DNSinterface"]))
				{
					if($_POST["DNSinterface"] === "single")
					{
						$DNSinterface = "single";
					}
					elseif($_POST["DNSinterface"] === "all")
					{
						$DNSinterface = "all";
					}
					else
					{
						$DNSinterface = "local";
					}
				}
				else
				{
					// Fallback
					$DNSinterface = "local";
				}
				exec("sudo pihole -a -i ".$DNSinterface." -web");

				// If there has been no error we can save the new DNS server IPs
				if(!strlen($error))
				{
					$IPs = implode (",", $DNSservers);
					$return = exec("sudo pihole -a setdns \"".$IPs."\" ".$extra);
					$success .= htmlspecialchars($return)."<br>";
					$success .= "The DNS settings have been updated (using ".$DNSservercount." DNS servers)";
				}
				else
				{
					$error .= "The settings have been reset to their previous values";
				}

				break;

			// Set query logging
			case "Logging":

				if($_POST["action"] === "Disable")
				{
					exec("sudo pihole -l off");
					$success .= "Logging has been disabled and logs have been flushed";
				}
				elseif($_POST["action"] === "Disable-noflush")
				{
					exec("sudo pihole -l off noflush");
					$success .= "Logging has been disabled, your logs have <strong>not</strong> been flushed";
				}
				else
				{
					exec("sudo pihole -l on");
					$success .= "Logging has been enabled";
				}

				break;

			// Set domains to be excluded from being shown in Top Domains (or Ads) and Top Clients
			case "API":

				// Explode the contents of the textareas into PHP arrays
				// \n (Unix) and \r\n (Win) will be considered as newline
				// array_filter( ... ) will remove any empty lines
				$domains = array_filter(preg_split('/\r\n|[\r\n]/', $_POST["domains"]));
				$clients = array_filter(preg_split('/\r\n|[\r\n]/', $_POST["clients"]));

				$domainlist = "";
				$first = true;
				foreach($domains as $domain)
				{
					if(!validDomainWildcard($domain) || validIP($domain))
					{
						$error .= "Top Domains/Ads entry ".htmlspecialchars($domain)." is invalid (use only domains)!<br>";
					}
					if(!$first)
					{
						$domainlist .= ",";
					}
					else
					{
						$first = false;
					}
					$domainlist .= $domain;
				}

				$clientlist = "";
				$first = true;
				foreach($clients as $client)
				{
					if(!validDomainWildcard($client) && !validIP($client))
					{
						$error .= "Top Clients entry ".htmlspecialchars($client)." is invalid (use only host names and IP addresses)!<br>";
					}
					if(!$first)
					{
						$clientlist .= ",";
					}
					else
					{
						$first = false;
					}
					$clientlist .= $client;
				}

				// Set Top Lists options
				if(!strlen($error))
				{
					// All entries are okay
					exec("sudo pihole -a setexcludedomains ".$domainlist);
					exec("sudo pihole -a setexcludeclients ".$clientlist);
					$success .= "The API settings have been updated<br>";
				}
				else
				{
					$error .= "The settings have been reset to their previous values";
				}

				// Set query log options
				if(isset($_POST["querylog-permitted"]) && isset($_POST["querylog-blocked"]))
				{
					exec("sudo pihole -a setquerylog all");
					if(!isset($_POST["privacyMode"]))
					{
						$success .= "All entries will be shown in Query Log";
					}
					else
					{
						$success .= "Only blocked entries will be shown in Query Log";
					}
				}
				elseif(isset($_POST["querylog-permitted"]))
				{
					exec("sudo pihole -a setquerylog permittedonly");
					if(!isset($_POST["privacyMode"]))
					{
						$success .= "Only permitted will be shown in Query Log";
					}
					else
					{
						$success .= "No entries will be shown in Query Log";
					}
				}
				elseif(isset($_POST["querylog-blocked"]))
				{
					exec("sudo pihole -a setquerylog blockedonly");
					$success .= "Only blocked entries will be shown in Query Log";
				}
				else
				{
					exec("sudo pihole -a setquerylog nothing");
					$success .= "No entries will be shown in Query Log";
				}


				if(isset($_POST["privacyMode"]))
				{
					exec("sudo pihole -a privacymode true");
					$success .= " (privacy mode enabled)";
				}
				else
				{
					exec("sudo pihole -a privacymode false");
				}

				break;

			case "webUI":
				if($_POST["tempunit"] == "F")
				{
					exec('sudo pihole -a -f');
				}
				elseif($_POST["tempunit"] == "K")
				{
					exec('sudo pihole -a -k');
				}
				else
				{
					exec('sudo pihole -a -c');
				}
				$adminemail = trim($_POST["adminemail"]);
				if(strlen($adminemail) == 0 || !isset($adminemail))
				{
					$adminemail = 'noadminemail';
				}
				elseif(!filter_var($adminemail, FILTER_VALIDATE_EMAIL) || strpos($adminemail, "'") !== false)
				{
					$error .= "Administrator email address (".htmlspecialchars($adminemail).") is invalid!<br>";
				}
				else
				{
					exec('sudo pihole -a -e \''.$adminemail.'\'');
				}
				if(isset($_POST["boxedlayout"]))
				{
					exec('sudo pihole -a layout boxed');
				}
				else
				{
					exec('sudo pihole -a layout traditional');
				}
				$success .= "The webUI settings have been updated";
				break;

			case "poweroff":
				exec("sudo pihole -a poweroff");
				$success = "The system will poweroff in 5 seconds...";
				break;

			case "reboot":
				exec("sudo pihole -a reboot");
				$success = "The system will reboot in 5 seconds...";
				break;

			case "restartdns":
				exec("sudo pihole -a restartdns");
				$success = "The DNS server has been restarted";
				break;

			case "flushlogs":
				exec("sudo pihole -f");
				$success = "The Pi-hole log file has been flushed";
				break;

			case "DHCP":

				if(isset($_POST["addstatic"]))
				{
					$mac = $_POST["AddMAC"];
					$ip = $_POST["AddIP"];
					$hostname = $_POST["AddHostname"];

					if(!validMAC($mac))
					{
						$error .= "MAC address (".htmlspecialchars($mac).") is invalid!<br>";
					}
					$mac = strtoupper($mac);

					if(!validIP($ip) && strlen($ip) > 0)
					{
						$error .= "IP address (".htmlspecialchars($ip).") is invalid!<br>";
					}

					if(!validDomain($hostname) && strlen($hostname) > 0)
					{
						$error .= "Host name (".htmlspecialchars($hostname).") is invalid!<br>";
					}

					if(strlen($hostname) == 0 && strlen($ip) == 0)
					{
						$error .= "You can not omit both the IP address and the host name!<br>";
					}

					if(strlen($hostname) == 0)
						$hostname = "nohost";

					if(strlen($ip) == 0)
						$ip = "noip";

					// Test if this MAC address is already included
					readStaticLeasesFile();
					foreach($dhcp_static_leases as $lease) {
						if($lease["hwaddr"] === $mac)
						{
							$error .= "Static release for MAC address (".htmlspecialchars($mac).") already defined!<br>";
							break;
						}
						if($ip !== "noip" && $lease["IP"] === $ip)
						{
							$error .= "Static lease for IP address (".htmlspecialchars($ip).") already defined!<br>";
							break;
						}
					}

					if(!strlen($error))
					{
						exec("sudo pihole -a addstaticdhcp ".$mac." ".$ip." ".$hostname);
						$success .= "A new static address has been added";
					}
					break;
				}

				if(isset($_POST["removestatic"]))
				{
					$mac = $_POST["removestatic"];
					if(!validMAC($mac))
					{
						$error .= "MAC address (".htmlspecialchars($mac).") is invalid!<br>";
					}
					$mac = strtoupper($mac);

					if(!strlen($error))
					{
						exec("sudo pihole -a removestaticdhcp ".$mac);
						$success .= "The static address with MAC address ".htmlspecialchars($mac)." has been removed";
					}
					break;
				}

				if(isset($_POST["active"]))
				{
					// Validate from IP
					$from = $_POST["from"];
					if (!validIP($from))
					{
						$error .= "From IP (".htmlspecialchars($from).") is invalid!<br>";
					}

					// Validate to IP
					$to = $_POST["to"];
					if (!validIP($to))
					{
						$error .= "To IP (".htmlspecialchars($to).") is invalid!<br>";
					}

					// Validate router IP
					$router = $_POST["router"];
					if (!validIP($router))
					{
						$error .= "Router IP (".htmlspecialchars($router).") is invalid!<br>";
					}

					$domain = $_POST["domain"];

					// Validate Domain name
					if(!validDomain($domain))
					{
						$error .= "Domain name ".htmlspecialchars($domain)." is invalid!<br>";
					}

					$leasetime = $_POST["leasetime"];

					// Validate Lease time length
					if(!is_numeric($leasetime) || intval($leasetime) < 0)
					{
						$error .= "Lease time ".htmlspecialchars($leasetime)." is invalid!<br>";
					}

					if(isset($_POST["useIPv6"]))
					{
						$ipv6 = "true";
						$type = "(IPv4 + IPv6)";
					}
					else
					{
						$ipv6 = "false";
						$type = "(IPv4)";
					}

					if(isset($_POST["DHCP_rapid_commit"]))
					{
						$rapidcommit = "true";
					}
					else
					{
						$rapidcommit = "false";
					}

					if(!strlen($error))
					{
						exec("sudo pihole -a enabledhcp ".$from." ".$to." ".$router." ".$leasetime." ".$domain." ".$ipv6." ".$rapidcommit);
						$success .= "The DHCP server has been activated ".htmlspecialchars($type);
					}
				}
				else
				{
					exec("sudo pihole -a disabledhcp");
					$success = "The DHCP server has been deactivated";
				}

				break;

			case "adlists":
				foreach ($adlist as $key => $value)
				{
					if(isset($_POST["adlist-del-".$key]))
					{
						// Delete list
						exec("sudo pihole -a adlist del ".escapeshellcmd($value[1]));
					}
					elseif(isset($_POST["adlist-enable-".$key]) && !$value[0])
					{
						// Is not enabled, but should be
						exec("sudo pihole -a adlist enable ".escapeshellcmd($value[1]));

					}
					elseif(!isset($_POST["adlist-enable-".$key]) && $value[0])
					{
						// Is enabled, but shouldn't be
						exec("sudo pihole -a adlist disable ".escapeshellcmd($value[1]));
					}
				}

				if(strlen($_POST["newuserlists"]) > 1)
				{
					$domains = array_filter(preg_split('/\r\n|[\r\n]/', $_POST["newuserlists"]));
					foreach($domains as $domain)
					{
						exec("sudo pihole -a adlist add ".escapeshellcmd($domain));
					}
				}

				// Reread available adlists
				$adlist = readAdlists();
				break;

			case "privacyLevel":
				$level = intval($_POST["privacylevel"]);
				if($level >= 0 && $level <= 4)
				{
					// Check if privacylevel is already set
					if (isset($piholeFTLConf["PRIVACYLEVEL"])) {
						$privacylevel = intval($piholeFTLConf["PRIVACYLEVEL"]);
					} else {
						$privacylevel = 0;
					}

					// Store privacy level
					exec("sudo pihole -a privacylevel ".$level);

					if($privacylevel > $level)
					{
						exec("sudo pihole -a restartdns");
						$success .= "The privacy level has been decreased and the DNS resolver has been restarted";
					}
					elseif($privacylevel < $level)
					{
						$success .= "The privacy level has been increased";
					}
					else
					{
						$success .= "The privacy level has been not been changed";
					}
				}
				else
				{
					$error .= "Invalid privacy level (".$level.")!";
				}
				break;

			default:
				// Option not found
				$debug = true;
				break;
		}
	}

	// Credit: http://stackoverflow.com/a/5501447/2087442
	function formatSizeUnits($bytes)
	{
		if ($bytes >= 1073741824)
		{
			$bytes = number_format($bytes / 1073741824, 2) . ' GB';
		}
		elseif ($bytes >= 1048576)
		{
			$bytes = number_format($bytes / 1048576, 2) . ' MB';
		}
		elseif ($bytes >= 1024)
		{
			$bytes = number_format($bytes / 1024, 2) . ' kB';
		}
		elseif ($bytes > 1)
		{
			$bytes = $bytes . ' bytes';
		}
		elseif ($bytes == 1)
		{
			$bytes = $bytes . ' byte';
		}
		else
		{
			$bytes = '0 bytes';
		}

		return $bytes;
	}
?>
