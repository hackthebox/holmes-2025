<img src="./assets/banner.png" style="max-width: 100%; height: auto;" align=left />

# <center>Chapter 4 - The Tunnel Without Walls</center>

-----------

![img](./assets/ChallengeBanner.jpg)

-----------

<p align="center">
<img src="./assets/The_Tunnel_Without_Walls.png" style="max-width: 49%;"/>
</p>

2025-09-03

Prepared by: achille

Sherlock Author: achille

Difficulty: <font color="red">Hard</font>

## Scenario

```
A memory dump from a connected Linux machine reveals covert network connections, fake services, and unusual redirects. Holmes investigates further to uncover how the attacker is manipulating the entire network!
```

## Artifacts Provided

Enter the artifacts provided along with their file hash here.

- memdump.mem - *0cfcab88826a9cab26035cf14a73f348bcfc3bc90ef1d48cd1176baaad066156*

## Skills Learnt

* Linux Memory Forensics
* DHCP and DNS Spoofing
* Supply-Chain Attack

## Initial Analysis

----------

To begin the analysis, the password-protected ZIP file was unlocked using the password `hacktheblue` and then we can confirm the integrity of the memory dump.

![Memory dump hash](./Assets/memdump_hash.png)

First, we inspect the file and extract the initial information to understand what we are dealing with.

![Hexdump of the memory dump](./Assets/hexdump.png)

The **hexdump** output shows that the initial few bytes are `EmiL`, indicating that this is a memory dump captured with [LiME](https://github.com/504ensicsLabs/LiME), the Linux Memory Extractor. Next, we must determine which Linux kernel and distribution this dump came from.

## Questions

----------
1. **What is the Linux kernel version of the provided image?**

	**Volatility3** is probably one of the best tool to analyze memory dumps from different operating systems, including Linux systems. It has a very useful plugin called `banners` that attempts to identify potential Linux banners in an image.

	![Volatility3 banners plugin](./Assets/banners.png)
	
	As we can see from the output, it seems the memory dump came from a Debian OS running the Linux kernel `5.10.0-35-amd64`.  Armed with this information, we can answer the first question. However, to continue analyzing the image, we must create a profile for this operating system and load it into **Volatility3**.
	
	This [blog post](https://www.hackthebox.com/blog/how-to-create-linux-symbol-tables-volatility) by [c4n0pus](https://app.hackthebox.com/users/527470) explains very well how to proceed.
	
	By simply searching for `debian 5.10.0-35-amd64`, we can immediately access the Debian packages [page](https://packages.debian.org/bullseye/amd64/linux-image-5.10.0-35-amd64-dbg/download), where we can download the Linux image containing the debug symbols for the indicated version.
	
	![Linux image](./Assets/debian_package.png)
	
	After downloading the file, we can extract the uncompressed kernel image with full debug symbols, as well as the `System.map`. We will use both of these files to create the **Volatility3** profile with the **dwarf2json** tool, compress it and copy into the folder `<volatility3_root>/volatility3/symbols/linux/`.
	
	![dwarf2json](./Assets/dwarf2json.png)
	
	**Answer:** <span style="color: #9FEF00;">`5.10.0-35-amd64`</span>


2. **The attacker connected over SSH and executed initial reconnaissance commands. What is the PID of the shell they used?**

	When analyzing a Linux memory dump, one of the first plugins we can run is the `linux.bash` plugin to get an idea of the recent commands that have been run on the machine.

	![Bash history](./Assets/bash_history.png)
	
	We can see that some basic information-gathering commands were run from a `bash` process with PID `13608`. 
	
	**Answer:** <span style="color: #9FEF00;">`13608`</span>


3. **After the initial information gathering, the attacker authenticated as a different user to escalate privileges. Identify and submit that user's credentials. (user:password)**

	To gain a clearer understanding of the situation, we used the `linux.pstree` plugin to analyze the hierarchy of processes identified via the Bash history.

	![pstree plugin](./Assets/pstree.png)
	
	By comparing the output of the `linux.pstree` plugin with the Bash history, we can see that, when the memory capture occurred, two SSH sessions were running. The first session (in the red box) spawned a `bash` process (13608), which ran information-gathering commands. Then, it invoked su to switch to another user and spawned a second `bash` process (PID 22714). These seem to be the most likely `bash` processes used by the attacker. 
	
	The second session (blue box) appears to be the one used by the analyst to run **LiME** and capture the memory dump.
	
	
	
	Now, let's go back to the Bash history. It appears the attacker started a container by mapping the host's `/etc/` folder to the container's `/mnt` folder. Shortly afterwards, the attacker authenticated as user `jm`.
	
	The container logs could help reconstruct the actions in this case. Docker saves the container logs in the path `/var/lib/docker/containers/<container_id>/<container_id>-json.log`. 
	
	We can use the very powerful plugin, `linux.pagecache.Files`, to list files from memory along with their inode information and creation timestamp. We save the output to a file so then we can easily search into it.
	
	![json.log files](./Assets/json-log_files.png)
	
	Now, if we grep for "**json.log**" on the output file we find 10 files corresponding to 10 different containers. Looking at their creation timestamps, we see that the second file in the list was created just five seconds after the suspicious Docker command (`docker run -v /etc/:/mnt -it alpine`) found in the Bash history. Therefore, this log file most likely belongs to the container we are looking for.
	
	Let's extract this file from memory using the plugin `linux.pagecache.InodePages` with the INode address `0x9b3386436f80` and the `--dump` option.
	
	![jm user added to passwd](./Assets/jm_password.png)
	
	The container's logs clearly show that, after mapping the host's `/etc/` folder to the container's `/mnt` folder, the attacker added a new root user to the `/etc/passwd` file. The new user is named `jm` and the hashed password is `$1$jm$poAH2RyJp8ZllyUvIkxxd0`. 
	
	We finally attempt to crack the password using **hashcat** with **rockyou.txt** wordlist and this is the result.
	
	![Cracked password](./Assets/cracked_password.png)
	
	**Answer:** <span style="color: #9FEF00;">`jm:WATSON0`</span>


4. **The attacker downloaded and executed code from Pastebin to install a rootkit. What is the full path of the malicious file?**

	In Linux systems, attackers typically install rootkits by loading malicious kernel modules. **Volatility3** provides several useful plugins for checking the modules loaded by the system. These include `linux.lsmod` for regular modules and `linux.malware.hidden_modules` for hidden modules.

	After running `linux.lsmod` and not noticing anything unusual, we run `linux.malware.hidden_modules` and discover that a stealth module has been loaded: `Nullincrevenge`.
	
	![Hidden module](./Assets/hidden_module.png)
	
	We can use the previous file containing the `linux.pagecache.Files` plugin output to retrieve the full path of where the module resides.
	
	![Module full path](./Assets/module_fullpath.png)
	
	**Answer:** <span style="color: #9FEF00;">`/usr/lib/modules/5.10.0-35-amd64/kernel/lib/Nullincrevenge.ko`</span>


5. **What is the email account of the alleged author of the malicious file?**

	Now we can try to dump it from memory.

	![Dumped module](./Assets/dumped_module.png)
	
	And then analyze its metadata with **modinfo**.
	
	![modinfo](./Assets/modinfo.png)
	
	**Answer:** <span style="color: #9FEF00;">`i-am-the@network.now`</span>


6. **The next step in the attack involved issuing commands to modify the network settings and installing a new package. What is the name and PID of the package? (package name,PID)**

	Examining the Bash history, we see that the attacker interacted with the firewall program `iptables` and then installed the tool `dnsmasq`, which is used to create local network infrastructure. The following is part of its official description:

	```text
	Dnsmasq provides network infrastructure for small networks: DNS, DHCP, router advertisement and network boot. It is designed to be lightweight and have a small footprint, suitable for resource constrained routers and firewalls.
	```
	
	We can easily retrieve its PID by running the `linux.pslist` plugin (or `linux.pstree` again).
	
	![Dnsmasq](./Assets/dnsmasq.png)
	
	**Answer:** <span style="color: #9FEF00;">`dnsmasq,38687`</span>


7. **Clearly, the attacker's goal is to impersonate the entire network. One workstation was already tricked and got its new malicious network configuration. What is the workstation's hostname?**

	As outlined in the previous description, **Dnsmasq** can be configured to operate as a DHCP server, enabling it to dynamically allocate IP addresses, default gateways, and DNS resolvers to client workstations that broadcast DHCP discovery requests on the network. By examining the **Dnsmasq** man page, we can see that the service, by default, relies on specific system files to store and retrieve configuration, such as range addresses, lease information, and resolver settings.

	![Dnsmasq man page](./Assets/dnsmasq_manpage.png)
	
	To determine which workstations have already obtained network configuration from **Dnsmasq**, we are particularly interested in its lease files. Therefore we can search for them in the files list previously recovered and, if available, dump them.
	
	![Dnsmasq leases](./Assets/dnsmasq_leases.png)
	
	**Answer:** <span style="color: #9FEF00;">`Parallax-5-WS-3`</span>


8. **After receiving the new malicious network configuration, the user accessed the City of CogWork-1 internal portal from this workstation. What is their username?**

	Although we don't have access to the compromised workstation, all of its generated traffic now passes through the new malicious gateway, which is our machine.

	Therefore, we can try to extract fragments of network traffic from the memory dump using [**bulk_extractor**](https://github.com/simsong/bulk_extractor).
	
	```bash
	bulk_extractor -o extracted_data memdump.mem
	```
	
	**bulk_extractor** retrieves a lot of data and also a `packets.pcap` file, let's analyze it with **Wireshark**. 
	
	![Username from pcap](./Assets/wireshark.png)
	
	When we set the filter for **HTTP** traffic, we immediately see that the victim workstation (192.168.211.52) connected to a different server (10.129.232.25) on port 8081, which hosts the **CogWork-1 People Portal**. 
	
	We can see that the current user is `Mike.sullivan`.
	
	**Answer:** <span style="color: #9FEF00;">`Mike.sullivan`</span>


9. **Finally, the user updated a software to the latest version, as suggested on the internal portal, and fell victim to a supply chain attack. From which Web endpoint was the update downloaded?**

	The victim user browsed two pages on the **CogWork-1 People Portal**, `profile.php` and `tasks.php`. The second one contains a pending task that inform the user to update a software called **AetherDesk**.

	![Tasks page](./Assets/tasks_page.png)
	
	Currently, the attacker can intercept and redirect traffic wherever they want. Moreover, the Bash history indicates that the attacker spawned a second Docker container after installing **Dnsmasq** and interacting with **iptables**. 
	
	By comparing the timestamp of the `docker run` command with the creation timestamp of the `<container_id>-json.log` files, we can examine the logs from the `jm_proxy` container. This container is based on the nginx image and was executed with a custom `default.conf`.
	
	![jm_proxy container](./Assets/jm_proxy.png)
	
	Now let's dump it with `linux.pagecache.InodePages` plugin and review its content.
	
	![jm_proxy logs](./Assets/jm_proxy_logs.png)
	
	**Answer:** <span style="color: #9FEF00;">`/win10/update/CogSoftware/AetherDesk-v74-77.exe`</span>


10. **To perform this attack, the attacker redirected the original update domain to a malicious one. Identify the original domain and the final redirect IP address and port. (domain,IP:port)**

	To fully understand how the attacker manipulated the incoming traffic we must retrieve the **Dnsmasq** configuration. As we saw previously, the file that stores the settings is `/etc/dnsmasq.conf`. Let's retrieve and analyze it.

	![Dnsmasq.conf](./Assets/dnsmasq_conf.png)
	
	The configuration assigns our machine as the gateway and DNS resolver for client workstations that request DHCP. It then forwards all DNS requests to 8.8.8.8, except for requests to `updates.cogwork-1.net`, which are redirected to the machine itself.
	
	However, this is not the final redirect. As we saw earlier, the malicious update was downloaded inside the `jm_proxy` container. Therefore, we also need to retrieve the original `default.conf` file to determine the final redirect. As shown in the Bash history, the attacker created the file in the `/tmp` folder and then deleted it. Let's see if it is still available in memory.
	
	![default.conf](./Assets/default_conf.png)
	
	As we can see, the attacker intercepts requests to  `updates.cogwork-1.net` and redirects them to itself. There, an nginx proxy is listening on port 80 and redirects these requests again to `13.62.49.86:7477`.
	
	**Answer:** <span style="color: #9FEF00;">`updates.cogwork-1.net,13.62.49.86:7477`</span>

