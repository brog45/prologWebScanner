# prologWebScanner

> a web application scanner for use with SWI-Prolog

PrologWebScanner is a set of tools for using SWI-Prolog to find security issues in web applications. It includes passive auditing techniques and active "fuzzing" techniques. It was created for my own entertainment and education, but I hope to develop it into a reusable pack. 

**WARNING:** Never scan a target you don't own without permission. You could get in trouble using this code against a target someone else owns. People don't like being targetted for scans and might call the police on you. Fuzzing generates a lot of traffic. It may generate errors in the targeted web application. It may leave persistent data in the target's database that could continue to cause errors after the scan. 

## Table of Contents

- [Security](#security)
- [Background](#background)
- [Install](#install)
- [Usage](#usage)
- [API](#api)
- [Maintainers](#maintainers)
- [Contributing](#contributing)
- [License](#license)

## Security

I recommend running the target system on an isolated virtual network in a either virtual machine or a Docker container. Scans will run faster against a local, virtual target than they would over wi-fi or ethernet. Also, [VulHub](https://www.vulnhub.com) has many downloadable VM images of vulnerable systems, but you might not want to trust them with full access to your system, your network, and the internet. 

### VirtualBox 

VirtualBox supports Internal and Host-only network for your virtual machines. A host-only network allows the VM to connect to your regular machine. 

### Docker

Docker Compose lets you configure a system of containers with virtual networks.
Untrusted containers can be run on an isolated, `internal` network. 

## Install

### Prerequisites

It is unknown if this code will work with a version of SWI-Prolog before 7.7.15. You can install SWI-Prolog using [swivm](https://github.com/fnogatz/swivm/blob/master/README.md). If you prefer Docker, you can use the [swipl](https://hub.docker.com/_/swipl) image. 

The demonstration scripts `demo_fuzz_files.pl` and `demo_fuzz_har.pl` assume that an instance of either the [BadStore VM](https://www.vulnhub.com/entry/badstore-123,41/) or the [BadStore Docker image](https://hub.docker.com/r/jvhoof/badstore-docker) is running at IP address 192.168.56.101.

### Clone this repository

```sh
cd ~/src
git clone https://github.com/brog45/prologWebScanner.git
cd prologWebScanner
```

## Usage

The programs `demo_fuzz_files.pl` and `demo_fuzz_har.pl` demonstrate how to use the `webfuzz` module's predicates, `url_form_parameter_vulnerable/4` and `url_parameter_vulnerable/5`. 

### demo_fuzz_files.pl

`demo_fuzz_files.pl` demonstrates parsing GET and POST requests saved to text files `get.txt` and `post.txt` to drive fuzzing tests.

To run this script use this command at the shell prompt: 

```sh
swipl -s demo_fuzz_files.pl
```

This approach requires using a web proxy tool like BurpSuire or Fiddler to collect HTTP requests then manually copy and paste interesting requests to text files. I find this process tedious and it loses a lot of context in the process.

### demo_fuzz_har.pl

`demo_fuzz_har.pl` demonstrates parsing and auditing GET and POST requests saved to the HAR (HTTP archive) file `firefox.har` to both passively audit the session and actively fuzz.

To run this script use this command at the shell prompt: 

```sh
swipl -s demo_fuzz_har.pl
```

## API

### webfuzz

This module exports two predicates that actively fuzz a specified URL:

- `url_form_parameter_vulnerable(+Url, +FormPairs, -ParameterName, -Vulnerability) is nondet`<br>
  Posts mutated versions of `FormPairs` to `Url` and succeeds when parameter named `ParameterName` is found to be vulnerable to `Vulnerability`.

- `url_parameter_vulnerable(+Method, +Url, +FormPairs, -ParameterName, -Vulnerability) is nondet`<br>
  Tests `Url` for vulnerable parameters and succeeds when parameter named `ParameterName` is found to be vulnerable to `Vulnerability`.

## Contributing

PRs accepted. 

## License

MIT © 2019 [Brian Rogers](https://github.com/brog45)
