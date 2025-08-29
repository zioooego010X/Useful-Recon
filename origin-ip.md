# What does "origin IP" mean? :

  Many services today utilize various Content Delivery Network (CDN) providers, such as Cloud Flare, Akamai, and Amazon CloudFront. These providers are designed to protect and support web servers by acting as reverse proxies, handling all incoming traffic.

  This achieves several important objectives, including:

  - DDoS protection: CDNs offer protection against Distributed Denial of Service (DDoS) attacks by absorbing and mitigating the impact of malicious traffic.

  - Load balancing: CDNs distribute incoming traffic across multiple servers, preventing any single server from becoming overloaded and ensuring high availability and reliability.

  - Content caching: CDNs store copies of static content (such as images, CSS, and JavaScript files) on servers closer to users, thereby reducing latency and load times.
When you make an HTTP request to a domain, you are actually making a request to the CDN provider that the domain is using. This means you cannot retrieve the real server IP address

## Why is this important?

  Understanding the server's origin IP is crucial for accurately assessing vulnerabilities and potential security risks. This knowledge enables both threat actors and penetration testers to:

  - Precisely map the network infrastructure and identify services operating on various IP addresses.

  - Make direct HTTP requests that bypass CDN filtering mechanisms, potentially exposing multiple attack vectors

## Techniques and methods

  ### 1- manual way : 

  #### method 1 :
  First, we can use the host and whois utilities to gather more information about the domain in question:

    ```
    @deadsec ➜ ~  host example.com 
    example.com  has address 172.66.XX.XX
    example.com  has address 162.159.XX.XX
    ```

    ```
    @deadsec ➜ ~  whois 172.66.XX.XX
    ...
    NetRange:       172.64.0.0 - 172.71.255.255
    NetName:        CLOUDFLARENET
    OrgName:        Cloudflare, Inc.
    ...
    
  - From the information above, we can see that this IP address is owned by Cloudflare. This indicates that all our requests are routed through the CDN

#### method 2 : SSL-ceritifcates analysis 

  SSL certificates provide another valuable avenue for discovering a server's origin IP address. When a server hosts an SSL certificate,
  various details about the certificate, including its public key, can be used to trace back to the original server,
  even when the server is behind a CDN. Tools like Censys and CRT.sh can help a lot with certificate analysys.

#### We will use Censys to verify the certificate associated with a domain. At https://search.censys.io/ we are presented with a clean and concise interface:
<img width="953" height="366" alt="11" src="https://github.com/user-attachments/assets/a768d5ea-c312-4924-9193-019adde8ce6f" />

After entering our domain, we receive numerous responses:

<img width="938" height="440" alt="22" src="https://github.com/user-attachments/assets/34224935-7447-4afc-be43-0ade7d0ffff3" />

Let's examine the first IP address in the results:

<img width="931" height="228" alt="33" src="https://github.com/user-attachments/assets/f301f1ae-99fb-4380-933e-506ede70968e" />

This provides us with a wealth of valuable information.
In the Forward DNS and Names sections, we see the associated domains and names, respectively. This helps us identify the owner of the IP address.
As we can see, this IP address belongs to our target:

`Forward DNS: api-event.kr~~~~~~ , ec2-3-93-92-~~~~~~~.amazonaws.com ...`

By using curl on that IP with custom Host header value, we observe that we have found the correct IP address:

`$ curl -v http://52.19.60.183/ -H 'Host: example.com'`

#### Response:

```
HTTP/1.1 301 Moved Permanently
Content-Type: text/html
Location: https://example.com:443/

<html>
<head><title>301 Moved Permanently</title></head>
<body>
<center><h1>301 Moved Permanently</h1></center>
```
#### method 3 : 

#### Subdomains analysis: 
Occasionally, some subdomains are not routed through the CDN
and might expose the real IP address.
This often includes mail servers, FTP servers, and other similar services.
We can use Subfinder to identify different subdomains associated with enji.ai as follows:

```
$ subfinder -d example.com
[INF] Enumerating subdomains for example.com
...
doc.example.com
...
```
As shown, there is a documentation endpoint docs.enji.ai, which might not be routed through the CDN. Let's investigate this further.
We will use the host command to check if the CDN is present:
```
$ host doc.example.com
doc.example.com has address 172.66.0.96
doc.example.com has address 162.159.140.98
```

#### method 4 : 
#### DNS Records Analysis

By examining the DNS records of a domain, an attacker could potentially discover previously exposed IP addresses of the server
from times when it was not behind a CDN. DNS records provide various types of information about a domain,
and by analyzing these records, penetration testers can gather valuable insights that may lead to the discovery of the origin IP.

#### Types of DNS records
Different types of DNS records can reveal specific details about the domain and its infrastructure:

- A Records: These records map a domain name to an IPv4 address. By examining historical A records, one can find previous IP addresses that may have been used by the domain before switching to a CDN.

- AAAA Records: Similar to A records but for IPv6 addresses. Historical AAAA records can also provide information on previous IPv6 addresses.

- MX Records: Mail Exchange records specify the mail servers responsible for receiving email on behalf of the domain. Sometimes, these mail servers are not routed through the CDN, revealing the real IP address.

- TXT Records: Text records can contain various forms of information, including verification details for email services and other metadata. Occasionally, these records might inadvertently expose internal IP addresses or other sensitive information.

- CNAME Records: Canonical Name records alias one domain to another. By following the chain of CNAME records, it’s possible to uncover the origin domain that might point directly to the real server IP.

 We can use the dig command to find the real IP address through DNS records.
 By querying the DNS records of a domain, dig provides detailed information about the IP addresses associated with the domain.
 Running dig on example.com outputs the following:

```
 ...
example.com                0       IN      A       167.179.170.78
example.com                0       IN      A       172.76.0.76
...

```

This output shows that the example.com resolves to two IP addresses, 167.179.170.78 and 172.76.0.76,
both of which are associated with Cloudflare. However, when we run dig on subdomains like doc.example.com or auth.example.com, the results are different:
```
...
a33...075.eu-west-1.elb.amazonaws.com. 0 IN A 32.13.60.133
a33...075.eu-west-1.elb.amazonaws.com. 0 IN A 32.33.79.236
...
```

We can see that the subdomains doc.example.com and auth.example.com resolve to the CNAME record a33...075.eu-~~~~~~.amazonaws.com,
which in turn resolves to the IP addresses  32.13.60.133 (which is our real IP adress) and 32.33.79.236.
By identifying such records, we can often bypass the CDN and uncover the real IP addresses of the servers hosting these subdomains

#### CDN IP ranges
Given that example.com is hosted on AWS, we can utilize CN/SANs of all Amazon's IPs to identify the IP address associated with our domain. This can be accomplished with the following command:


```How do i find IP ranges of different providers? This particular `amazon-ipv4-sni.txt` dictionary was found on `kaeferjaeger.gay/sni-ip-ranges/amazon`. You can easily find one on the internet.```

```
$ cat amazon-ipv4-sni.txt | grep example.com
...
32.13.60.133:443 -- [example.com *.example.com *.example.com *.example.com *.example.com example.com]
...
```

In this instance, the identified IP address is now associated with a different domain,
rendering it irrelevant for our current needs. However,
this method remains highly valuable for uncovering the actual IP address of different domains in future engagements.

#### Additional methods

Here are some additional techniques that can assist in uncovering the real IP address of the server:

- Host header fuzzing: Even such things as Host header fuzzing using various subdomains and loopback IPs can occasionally bypass a CDN, enabling direct HTTP requests.

- WordPress pingback: In the case of WordPress, there is an interesting technique called pingback that sometimes allows an attacker to retrieve the real IP address of the server. For a detailed explanation, you can refer to this excellent article.

- Social engineering: Threat actors could use diverse social engineering techniques to uncover real IP addresses. Methods such as phishing, pretexting, and even physical reconnaissance (like dumpster diving) can potentially yield that missing piece of valuable information such as IP adress.


# Automation way : 
just running this tools 😃

### Useful tools : 
- [CloudFlair](https://github.com/christophetd/CloudFlair)

- [originip](https://github.com/rix4uni/originip)

- [CloudFail](https://github.com/H4CK3RT3CH/CloudFail)


#### some writeups : 
[https://bevijaygupta.medium.com/bypass-firewall-by-finding-origin-ip-132cf675c0c8](https://bevijaygupta.medium.com/bypass-firewall-by-finding-origin-ip-132cf675c0c8)
[https://infosecwriteups.com/bypass-firewall-by-finding-origin-ip-41ba984e1342](https://infosecwriteups.com/bypass-firewall-by-finding-origin-ip-41ba984e1342)
[https://infosecwriteups.com/finding-the-origin-ip-part-2-c96d7488c40e](https://infosecwriteups.com/finding-the-origin-ip-part-2-c96d7488c40e)
[https://infosecwriteups.com/this-tool-helped-me-to-find-origin-ip-automated-way-9a95632d65fe](https://infosecwriteups.com/this-tool-helped-me-to-find-origin-ip-automated-way-9a95632d65fe)

